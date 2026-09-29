"""Per-user "Connect Google": the OAuth authorization-code flow and refresh
(D3, D4, D8, D9).

Flow::

    GET /-/google-auth/connect?return_to=/some/path     start_connect()
      -> 302 Google consent screen (PKCE S256, signed state)
    GET /-/google-auth/oauth/callback?code=...&state=...  finish_connect()
      -> code exchange, userinfo, upsert by (owner, sub), 302 return_to

Forgery defences, in the order the callback checks them:

* ``state`` is ``datasette.sign({"a": actor_id, "r": return_to, "n": nonce,
  "t": issued_at}, namespace=STATE_NAMESPACE)``: tamper-proof, and bound to
  the actor who started the flow and to a 10-minute window.
* The nonce must match the one in the flow cookie (``FLOW_COOKIE``: signed,
  HttpOnly, SameSite=Lax, 10 minutes, scoped to ``/-/google-auth/``), so a
  state lifted from someone else's browser is useless without their cookie.
* The PKCE ``code_verifier`` lives only in that cookie; Google refuses the
  code exchange without it.

Both routes are GETs reached by top-level redirects, so Datasette's CSRF
middleware (which only inspects unsafe methods) never blocks them.

Only the refresh token is persisted, encrypted as ``{"refresh_token": ...}``.
Access tokens go to the in-memory token cache. Nothing here logs, and no
response, error message or flash contains a code, verifier or token.
"""

from __future__ import annotations

import re
import secrets
import time
from base64 import urlsafe_b64encode
from collections.abc import Iterable
from dataclasses import dataclass, field
from hashlib import sha256
from typing import TYPE_CHECKING, Any
from urllib.parse import unquote, urlencode, urlparse

import httpx2
from datasette import Forbidden, NotFound, Response

from .config import REQUIRED_SCOPES, Config, get_config, oauth_configured
from .crypto import decrypt_credential, encrypt_secret, require_box
from .errors import (
    CredentialBroken,
    CredentialChanged,
    CredentialNotFound,
    EncryptionNotConfigured,
    GoogleTokenError,
)
from .events import (
    CredentialCreatedEvent,
    CredentialReconnectedEvent,
    mark_broken,
    track_credential_event,
)
from .http import client, google_error
from .internal_db import CredentialRow, InternalDB
from .permissions import can_connect
from .token_cache import CacheKey, TokenCache, get_token_cache
from .tokens import Token

if TYPE_CHECKING:
    from datasette.app import Datasette
    from datasette.utils.asgi import Request

TYPE = "google_oauth"

CONNECT_PATH = "/-/google-auth/connect"
CALLBACK_PATH = "/-/google-auth/oauth/callback"
DEFAULT_RETURN_TO = "/-/google-auth"
# The flow cookie is only sent to our own routes.
COOKIE_PATH = "/-/google-auth/"

STATE_NAMESPACE = "google-auth-oauth"
FLOW_COOKIE = "google_auth_oauth"
FLOW_COOKIE_NAMESPACE = "google-auth-oauth-flow"
FLOW_MAX_AGE = 600
"""Seconds a connect attempt stays valid: the cookie's max-age and the
state's maximum age."""
# How far in the future a state's timestamp may be (clock drift between
# processes).
_CLOCK_SKEW = 60

BROKEN_DETAIL = "Google access was revoked or expired — reconnect"
NO_REFRESH_TOKEN = (
    "Google didn't return a refresh token — remove the app at"
    " myaccount.google.com/permissions and try again"
)

_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")
_ERROR_CODE = re.compile(r"^[a-z_]{1,64}$")


# --- URLs -------------------------------------------------------------------


def safe_return_to(value: str | None, default: str = DEFAULT_RETURN_TO) -> str:
    """``value`` if it is a same-origin path, else ``default``.

    Open-redirect guard: must start with ``/``; not ``//`` or ``/\\``; no
    backslash, scheme, authority or control character (CR/LF included), in
    either the given or the URL-decoded form (browsers strip tab/CR/LF, so
    ``/\\t/evil.com`` must not be judged on its literal form).
    """
    if not value:
        return default
    for candidate in (value, unquote(value)):
        if any(c < " " or c == "\x7f" for c in candidate):
            return default
        if "\\" in candidate:
            return default
        if not candidate.startswith("/") or candidate.startswith("//"):
            return default
        if _SCHEME.match(candidate):
            return default
        parsed = urlparse(candidate)
        if parsed.scheme or parsed.netloc:
            return default
    return value


def connect_url(datasette: Datasette, return_to: str | None = None) -> str:
    """The path that starts (or restarts) "Connect Google", for reconnect
    links on ``CredentialBroken`` / ``MissingScopes`` and for consumers
    bouncing a user through connect."""
    path = datasette.urls.path(CONNECT_PATH)
    if return_to:
        path += "?" + urlencode({"return_to": return_to})
    return path


def redirect_uri(datasette: Datasette, request: Request, config: Config) -> str:
    """The OAuth redirect URI: the configured override, or the absolute URL of
    the callback. Built the same way at both ends of the flow, as Google
    requires them to match."""
    if config.redirect_uri:
        return config.redirect_uri
    return datasette.absolute_url(request, datasette.urls.path(CALLBACK_PATH))


# --- PKCE, state, flow cookie -----------------------------------------------


def make_pkce() -> tuple[str, str]:
    """A PKCE ``(code_verifier, S256 code_challenge)`` pair (RFC 7636).

    86-character verifier from the unreserved alphabet (43–128 allowed).
    """
    verifier = secrets.token_urlsafe(64)
    challenge = urlsafe_b64encode(sha256(verifier.encode("ascii")).digest())
    return verifier, challenge.rstrip(b"=").decode("ascii")


@dataclass(frozen=True)
class FlowState:
    actor_id: str
    return_to: str
    nonce: str
    issued_at: int


def sign_state(datasette: Datasette, state: FlowState) -> str:
    return datasette.sign(
        {
            "a": state.actor_id,
            "r": state.return_to,
            "n": state.nonce,
            "t": state.issued_at,
        },
        namespace=STATE_NAMESPACE,
    )


def read_state(datasette: Datasette, signed: str | None) -> FlowState | None:
    """The signed ``state`` parameter, or None if missing or tampered with.
    Doesn't check its age: see ``_check_state``."""
    if not signed:
        return None
    try:
        payload = datasette.unsign(signed, namespace=STATE_NAMESPACE)
    except Exception:
        # Bad signature or malformed value: never a 500.
        return None
    if not isinstance(payload, dict):
        return None
    actor_id, return_to = payload.get("a"), payload.get("r")
    nonce, issued_at = payload.get("n"), payload.get("t")
    if not (
        isinstance(actor_id, str)
        and isinstance(return_to, str)
        and isinstance(nonce, str)
        and isinstance(issued_at, int)
    ):
        return None
    return FlowState(actor_id, safe_return_to(return_to), nonce, issued_at)


def _read_flow_cookie(datasette: Datasette, request: Request) -> dict[str, str] | None:
    """``{"v": code_verifier, "n": nonce}`` from the flow cookie, or None."""
    raw = request.cookies.get(FLOW_COOKIE)
    if not raw:
        return None
    try:
        payload = datasette.unsign(raw, namespace=FLOW_COOKIE_NAMESPACE)
    except Exception:
        return None
    if (
        not isinstance(payload, dict)
        or not isinstance(payload.get("v"), str)
        or not isinstance(payload.get("n"), str)
    ):
        return None
    return payload


def _secure_cookie(datasette: Datasette, request: Request) -> bool:
    return request.scheme == "https" or bool(datasette.setting("force_https_urls"))


def _set_flow_cookie(
    datasette: Datasette,
    request: Request,
    response: Response,
    *,
    verifier: str,
    nonce: str,
) -> None:
    response.set_cookie(
        FLOW_COOKIE,
        datasette.sign({"v": verifier, "n": nonce}, namespace=FLOW_COOKIE_NAMESPACE),
        max_age=FLOW_MAX_AGE,
        path=datasette.urls.path(COOKIE_PATH),
        secure=_secure_cookie(datasette, request),
        httponly=True,
        samesite="lax",
    )


def _clear_flow_cookie(datasette: Datasette, response: Response) -> None:
    response.set_cookie(
        FLOW_COOKIE,
        "",
        max_age=0,
        expires=0,
        path=datasette.urls.path(COOKIE_PATH),
        httponly=True,
        samesite="lax",
    )


# --- Routes -----------------------------------------------------------------


def _actor_id(actor: dict[str, Any] | None) -> str | None:
    if not actor or actor.get("id") is None:
        return None
    return str(actor["id"])


async def _require_connect(datasette: Datasette, request: Request) -> str:
    """404 without OAuth config; 403 unless the actor may connect.

    Raising ``Forbidden`` (rather than returning a 403) lets a login plugin's
    ``forbidden()`` hook send anonymous users to sign in.
    """
    if not oauth_configured(get_config(datasette)):
        # No setup page until the management UI exists (ticket 14).
        raise NotFound("Connect Google is not configured on this instance")
    actor_id = _actor_id(request.actor)
    if actor_id is None or not await can_connect(datasette, request.actor):
        raise Forbidden("You don't have permission to connect a Google account")
    return actor_id


async def _error_page(
    datasette: Datasette,
    request: Request,
    message: str,
    *,
    status: int = 400,
    title: str = "Google connection failed",
) -> Response:
    """Datasette's error page, with the flow cookie cleared. ``message`` is
    auto-escaped and must never contain a code, token or verifier."""
    response = Response.html(
        await datasette.render_template(
            "error.html",
            {"ok": False, "error": message, "status": status, "title": title},
            request=request,
        ),
        status=status,
    )
    _clear_flow_cookie(datasette, response)
    return response


async def start_connect(datasette: Datasette, request: Request) -> Response:
    """``GET /-/google-auth/connect?return_to=/path``: redirect to Google."""
    actor_id = await _require_connect(datasette, request)
    try:
        require_box(datasette)
    except EncryptionNotConfigured as ex:
        return await _error_page(datasette, request, str(ex), status=503)
    config = get_config(datasette)
    return_to = safe_return_to(
        request.args.get("return_to"), datasette.urls.path(DEFAULT_RETURN_TO)
    )
    verifier, challenge = make_pkce()
    nonce = secrets.token_urlsafe(16)
    state = sign_state(
        datasette, FlowState(actor_id, return_to, nonce, int(time.time()))
    )
    params = {
        "client_id": config.client_id or "",
        "redirect_uri": redirect_uri(datasette, request, config),
        "response_type": "code",
        "scope": " ".join(config.scopes),
        "access_type": "offline",
        "prompt": "consent",
        "include_granted_scopes": "true",
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    authorize = config.google_base_urls.oauth_authorize
    separator = "&" if "?" in authorize else "?"
    response = Response.redirect(authorize + separator + urlencode(params))
    _set_flow_cookie(datasette, request, response, verifier=verifier, nonce=nonce)
    return response


def _check_state(
    state: FlowState | None,
    cookie: dict[str, str] | None,
    actor_id: str,
    *,
    now: float,
) -> str | None:
    """Why this callback can't be trusted, or None if it can."""
    if state is None:
        return "This Google connection attempt is invalid. Please try connecting again."
    if now - state.issued_at > FLOW_MAX_AGE or state.issued_at > now + _CLOCK_SKEW:
        return "This Google connection attempt expired. Please try connecting again."
    if cookie is None or not secrets.compare_digest(cookie["n"], state.nonce):
        return (
            "This Google connection attempt doesn't match this browser session."
            " Please try connecting again."
        )
    if not secrets.compare_digest(state.actor_id, actor_id):
        return (
            "This Google connection was started by a different user."
            " Please sign in as that user, or start again."
        )
    return None


async def finish_connect(datasette: Datasette, request: Request) -> Response:
    """``GET /-/google-auth/oauth/callback``: Google redirects back here."""
    actor_id = await _require_connect(datasette, request)
    state = read_state(datasette, request.args.get("state"))
    cookie = _read_flow_cookie(datasette, request)
    problem = _check_state(state, cookie, actor_id, now=time.time())
    if problem is not None or state is None or cookie is None:
        return await _error_page(datasette, request, problem or "Invalid request")

    error = request.args.get("error")
    if error:
        if error == "access_denied":
            message = "Google connection cancelled"
        elif _ERROR_CODE.match(error):
            message = f"Google connection failed: {error}"
        else:
            message = "Google connection failed"
        datasette.add_message(request, message, datasette.WARNING)
        return _redirect(datasette, state.return_to)

    code = request.args.get("code")
    if not code:
        return await _error_page(
            datasette, request, "Google didn't return an authorization code."
        )
    config = get_config(datasette)
    try:
        require_box(datasette)
        async with client(datasette) as http:
            granted = await exchange_code(
                http,
                config,
                code=code,
                code_verifier=cookie["v"],
                redirect_uri=redirect_uri(datasette, request, config),
            )
            if not granted.refresh_token:
                return await _error_page(datasette, request, NO_REFRESH_TOKEN)
            sub, email = await fetch_userinfo(http, config, granted.token.access_token)
    except CredentialBroken as ex:
        # invalid_grant on the code: reused, expired, or PKCE mismatch.
        return await _error_page(
            datasette,
            request,
            f"Google rejected the connection attempt ({ex.detail})."
            " Please try connecting again.",
        )
    except EncryptionNotConfigured as ex:
        return await _error_page(datasette, request, str(ex), status=503)
    except GoogleTokenError as ex:
        return await _error_page(datasette, request, str(ex), status=502)

    scopes = sorted(granted.token.scopes)
    idb = InternalDB(datasette.get_internal_database())
    row, created = await idb.upsert_oauth(
        actor_id,
        sub,
        google_email=email,
        label=email or f"Google account {sub}",
        scopes=scopes,
        secret_encrypted=encrypt_secret(
            datasette, {"refresh_token": granted.refresh_token}
        ),
        actor_id=actor_id,
    )
    # The fresh access token is good for an hour: cache it rather than
    # refreshing on first use. Evict first so a reconnect drops old tokens.
    cache = get_token_cache(datasette)
    cache.evict(row.id)
    await _seed(cache, oauth_cache_key(row), granted.token)
    await track_credential_event(
        datasette,
        CredentialCreatedEvent if created else CredentialReconnectedEvent,
        row,
        request.actor,
    )

    datasette.add_message(request, f"Connected Google account {row.label}")
    # openid/email are left out: userinfo just proved them, and Google may
    # report `email` under an alias (…/auth/userinfo.email) in `scope`.
    missing = [
        scope
        for scope in config.scopes
        if scope not in REQUIRED_SCOPES and scope not in granted.token.scopes
    ]
    if missing:
        datasette.add_message(
            request,
            "Google didn't grant all the requested access (missing: "
            + ", ".join(missing)
            + "). Reconnect and tick every box to fix this.",
            datasette.WARNING,
        )
    return _redirect(datasette, state.return_to)


def _redirect(datasette: Datasette, return_to: str) -> Response:
    # Re-validated here too: the state is signed, but belt and braces.
    response = Response.redirect(
        safe_return_to(return_to, datasette.urls.path(DEFAULT_RETURN_TO))
    )
    _clear_flow_cookie(datasette, response)
    return response


# --- Google token endpoint and userinfo --------------------------------------


@dataclass(frozen=True)
class GrantedToken:
    """A token-endpoint reply: the access token, plus a refresh token if
    Google issued one (always on code exchange, sometimes on refresh)."""

    token: Token
    refresh_token: str | None = field(default=None, repr=False)


def _parse_token_reply(
    response: httpx2.Response, fallback_scopes: Iterable[str]
) -> GrantedToken:
    if response.status_code != 200:
        error, description = google_error(response)
        if error == "invalid_grant":
            raise CredentialBroken(description or "invalid_grant")
        raise GoogleTokenError(response.status_code, error, description)
    try:
        body = response.json()
    except ValueError:
        body = None
    if not isinstance(body, dict):
        raise GoogleTokenError(200, "invalid_response", "reply is not a JSON object")
    access_token = body.get("access_token")
    if not isinstance(access_token, str) or not access_token:
        raise GoogleTokenError(200, "invalid_response", "no access_token in reply")
    # RFC 6749 5.1: an omitted `scope` means "as requested".
    scope = body.get("scope")
    scopes = scope.split() if isinstance(scope, str) else list(fallback_scopes)
    expires_in = body.get("expires_in")
    refresh_token = body.get("refresh_token")
    return GrantedToken(
        token=Token.from_expires_in(
            access_token,
            expires_in if isinstance(expires_in, (int, float)) else None,
            scopes,
        ),
        refresh_token=refresh_token
        if isinstance(refresh_token, str) and refresh_token
        else None,
    )


async def _post_token(
    http: httpx2.AsyncClient, config: Config, data: dict[str, str]
) -> httpx2.Response:
    try:
        return await http.post(config.google_base_urls.oauth_token, data=data)
    except httpx2.HTTPError as ex:
        # The exception text may include the request; the class name is enough.
        raise GoogleTokenError(None, type(ex).__name__) from None


async def exchange_code(
    http: httpx2.AsyncClient,
    config: Config,
    *,
    code: str,
    code_verifier: str,
    redirect_uri: str,
) -> GrantedToken:
    """Exchange an authorization code (with its PKCE verifier) for tokens.

    Granted scopes come from the reply's ``scope`` field (a subset of what
    was asked if the user unticked a box). Raises ``CredentialBroken`` on
    ``invalid_grant`` (bad/used/expired code or verifier) and
    ``GoogleTokenError`` otherwise.
    """
    response = await _post_token(
        http,
        config,
        {
            "grant_type": "authorization_code",
            "code": code,
            "code_verifier": code_verifier,
            "client_id": config.client_id or "",
            "client_secret": config.client_secret or "",
            "redirect_uri": redirect_uri,
        },
    )
    return _parse_token_reply(response, config.scopes)


async def fetch_userinfo(
    http: httpx2.AsyncClient, config: Config, access_token: str
) -> tuple[str, str | None]:
    """``(sub, email)`` for a fresh access token, from OpenID userinfo.

    Userinfo rather than verifying the ``id_token``: no JWKS fetch, and the
    token was minted a moment ago over TLS from the token endpoint.
    """
    try:
        response = await http.get(
            config.google_base_urls.userinfo,
            headers={"Authorization": f"Bearer {access_token}"},
        )
    except httpx2.HTTPError as ex:
        raise GoogleTokenError(None, type(ex).__name__) from None
    if response.status_code != 200:
        error, description = google_error(response)
        raise GoogleTokenError(response.status_code, error, description)
    try:
        body = response.json()
    except ValueError:
        body = None
    sub = body.get("sub") if isinstance(body, dict) else None
    if not isinstance(sub, str) or not sub:
        raise GoogleTokenError(200, "invalid_response", "no sub in userinfo reply")
    email = body.get("email") if isinstance(body, dict) else None
    return sub, email if isinstance(email, str) and email else None


async def refresh_access_token(
    http: httpx2.AsyncClient,
    config: Config,
    refresh_token: str,
    *,
    scopes: Iterable[str] = (),
) -> GrantedToken:
    """Trade a refresh token for a new access token.

    ``scopes`` (the row's granted scopes) are used if Google's reply omits
    ``scope``. ``GrantedToken.refresh_token`` is set only if Google rotated
    it; the caller must persist it. Talks to Google only: raises
    ``CredentialBroken`` on ``invalid_grant`` without touching the database
    (``fetch_oauth_token`` marks the row), ``GoogleTokenError`` otherwise.
    """
    response = await _post_token(
        http,
        config,
        {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": config.client_id or "",
            "client_secret": config.client_secret or "",
        },
    )
    return _parse_token_reply(response, scopes)


async def revoke_token(datasette: Datasette, token: str) -> str | None:
    """Revoke a refresh token at Google (``google_base_urls.oauth_revoke``),
    which ends the whole grant. Best effort, for delete (D16).

    Returns ``None`` if Google confirmed it (HTTP 200), else why not, safe
    to show: Google's ``error`` / ``error_description`` or the network
    error's class name, never the token.
    """
    url = get_config(datasette).google_base_urls.oauth_revoke
    try:
        async with client(datasette) as http:
            response = await http.post(url, data={"token": token})
    except httpx2.HTTPError as ex:
        # The exception text may include the request (and so the token).
        return f"no response from Google ({type(ex).__name__})"
    if response.status_code == 200:
        return None
    error, description = google_error(response)
    reason = ": ".join(part for part in (error, description) if part)
    return f"HTTP {response.status_code}" + (f": {reason}" if reason else "")


# --- For the broker (ticket 10) ----------------------------------------------


def oauth_cache_key(row: CredentialRow) -> CacheKey:
    """The token-cache key for an OAuth credential: its access tokens carry
    the granted scopes, whatever a caller asks for."""
    return CacheKey.for_row(row, row.scopes)


async def _seed(cache: TokenCache, key: CacheKey, token: Token) -> None:
    async def cached() -> Token:
        return token

    await cache.get_or_fetch(key, cached)


async def fetch_oauth_token(
    datasette: Datasette, row: CredentialRow, *, actor_id: str
) -> Token:
    """A new access token for an OAuth credential: decrypt the refresh token,
    refresh, and persist a rotated refresh token.

    For the broker's ``TokenCache.get_or_fetch(oauth_cache_key(row), ...)``.
    The caller must already have re-read ``row`` and checked that
    ``actor_id`` owns it; this does no permission checks.

    On ``invalid_grant`` the row is marked broken, its cached tokens are
    evicted and ``CredentialBroken`` (with ``credential_id`` and a
    ``reconnect_url``) is raised.

    Both writes (rotated refresh token, broken status) are compare-and-swap
    on the secret blob that was decrypted. If the row changed in between (a
    reconnect, another process's rotation, lazy key re-encryption), nothing
    is written: the row is re-read and the fetch retried once, through the
    cache under the new row's key (a reconnect has usually seeded it
    already). Losing the race again raises ``CredentialChanged``; a row that
    vanished raises ``CredentialNotFound``. May also raise
    ``EncryptionNotConfigured``, ``CredentialUndecryptable`` or
    ``GoogleTokenError``.
    """
    if row.type != TYPE:
        raise ValueError(f"Not an OAuth credential: {row.id}")
    token = await _fetch_once(datasette, row, actor_id=actor_id)
    if token is not None:
        return token

    fresh = await InternalDB(datasette.get_internal_database()).get(row.id)
    if fresh is None or fresh.type != TYPE or fresh.owner_id != row.owner_id:
        raise CredentialNotFound(row.id)

    async def fetch_fresh() -> Token:
        retried = await _fetch_once(datasette, fresh, actor_id=actor_id)
        if retried is None:
            raise CredentialChanged(row.id)
        return retried

    return await get_token_cache(datasette).get_or_fetch(
        oauth_cache_key(fresh), fetch_fresh
    )


async def _fetch_once(
    datasette: Datasette, row: CredentialRow, *, actor_id: str
) -> Token | None:
    """One refresh for ``row``; None if a write lost the race (row changed)."""
    idb = InternalDB(datasette.get_internal_database())
    cache = get_token_cache(datasette)
    blob = row.secret_encrypted
    secret = await decrypt_credential(datasette, row)
    refresh_token = secret.get("refresh_token")
    try:
        if not isinstance(refresh_token, str) or not refresh_token:
            raise CredentialBroken("no refresh token stored")
        async with client(datasette) as http:
            granted = await refresh_access_token(
                http, get_config(datasette), refresh_token, scopes=row.scopes
            )
    except CredentialBroken:
        # Evicts the cache and fires the broken event only if the write lands.
        if not await mark_broken(datasette, row, BROKEN_DETAIL, actor_id=actor_id):
            # Reconnected meanwhile: the rejected secret is no longer stored.
            return None
        raise CredentialBroken(
            BROKEN_DETAIL,
            credential_id=row.id,
            reconnect_url=connect_url(datasette),
        ) from None

    if granted.refresh_token and granted.refresh_token != refresh_token:
        if not await idb.update_secret(
            row.id,
            encrypt_secret(datasette, {"refresh_token": granted.refresh_token}),
            actor_id=actor_id,
            expected_secret=blob,
        ):
            # Don't clobber a newer secret with one from a superseded grant.
            return None
        # update_secret bumps updated_at (D22), so the next lookup uses a new
        # cache key: seed it, or every call would refresh (and rotate) again.
        updated = await idb.get(row.id)
        cache.evict(row.id)
        if updated is not None:
            await _seed(cache, oauth_cache_key(updated), granted.token)
    return granted.token
