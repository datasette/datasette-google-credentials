"""The consumer broker API (D11): the one place other plugins get Google
credentials and tokens from.

    creds = await list_credentials(datasette, actor=actor, scopes=[SHEETS])
    cred = await get_credential(datasette, creds[0].id, actor=actor, scopes=[SHEETS])
    response = await cred.request("GET", url)

Access rules:

* **OAuth** credentials are owner-only: ``owner_id == actor["id"]``, checked
  here in code. ``datasette.allowed()`` is never called for one (D6, D19).
* **Service accounts** need ``google-service-account-use``, via the
  type-gated ``sa_allowed_or_decoy``: every other actor and id (unknown, or
  someone else's OAuth credential) runs the same check against a decoy id, so
  it costs the same as an invisible service account (ticket 24).
* Anyone who can't use a credential and couldn't see it either gets
  ``CredentialNotFound``, exactly as for an id that doesn't exist (no ID
  probing). ``CredentialForbidden`` is only for actors who can see it but not
  use it: in v0, a ``google-credentials-admin`` looking at someone else's credential.

Revocation is immediate (D16): ``get_credential`` re-reads the row and
re-checks access, and so does **every** ``Credential.token()`` (and so
``request()``), so a ``Credential`` held across calls stops working the moment
its row is deleted, marked broken or unshared, even in another process. The
token cache is consulted only after that check. The cost is one internal-DB
query (plus one ``allowed()`` for a service account) per token, which is
small next to the Google call it precedes.

No secret, token or key material ever appears in a return value (other than
``token()``'s), an exception or a log line; this module doesn't log.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Iterable
from typing import TYPE_CHECKING, Any

import httpx2

from .config import get_config, oauth_configured
from .crypto import decrypt_credential
from .errors import (
    CredentialBroken,
    CredentialChanged,
    CredentialForbidden,
    CredentialNotFound,
    DisallowedHost,
    MissingScopes,
)
from .events import mark_broken
from .http import client
from .internal_db import CredentialRow, InternalDB
from .models import CredentialInfo
from .oauth import connect_url, fetch_oauth_token, oauth_cache_key
from .permissions import SA_USE, can_admin, sa_allowed_or_decoy, usable_sa_ids
from .service_account import ServiceAccountKey, mint_service_account_token
from .telemetry import credential_span, record_cache_lookup, request_call
from .telemetry_registry import CACHE, CREDENTIAL_TYPE, TOKEN
from .token_cache import CacheKey, get_token_cache
from .tokens import Token

if TYPE_CHECKING:
    from datasette.app import Datasette

OAUTH = "google_oauth"
SERVICE_ACCOUNT = "service_account"

SA_BROKEN_DETAIL = (
    "Google rejected this service account key (deleted or disabled?) — rotate the key"
)

# At most one last_used_* write per credential per this many seconds, per
# process: token() runs on every request() and must not hammer internal.db.
TOUCH_INTERVAL = 60.0

_TOUCH_ATTR = "_google_credentials_touch_throttle"

Actor = dict[str, Any] | None


# --- Scopes -----------------------------------------------------------------


_AUTH = "https://www.googleapis.com/auth/"

# D27: a granted scope also covers the narrower scopes Google accepts it for,
# so consumers can ask for the narrowest scope they need (the importer asks
# for spreadsheets.readonly) and still match a default, full-scope connect.
# Deliberately small: only pairs Alex decided on, nothing transitive.
SCOPE_IMPLIES: dict[str, frozenset[str]] = {
    _AUTH + "spreadsheets": frozenset({_AUTH + "spreadsheets.readonly"}),
    _AUTH + "drive": frozenset({_AUTH + "drive.readonly", _AUTH + "drive.file"}),
    # Two spellings of the same scope.
    "email": frozenset({_AUTH + "userinfo.email"}),
    _AUTH + "userinfo.email": frozenset({"email"}),
}


def covered_scopes(granted: Iterable[str]) -> set[str]:
    """``granted`` plus every scope it implies (``SCOPE_IMPLIES``)."""
    covered = set(granted)
    for scope in list(covered):
        covered |= SCOPE_IMPLIES.get(scope, frozenset())
    return covered


def missing_scopes(requested: Iterable[str], granted: Iterable[str]) -> list[str]:
    """The requested scopes not covered by ``granted``, sorted.

    A granted scope covers itself and the narrower scopes in
    ``SCOPE_IMPLIES`` (D27): ``spreadsheets`` covers
    ``spreadsheets.readonly``, never the other way round.
    """
    return sorted(set(requested) - covered_scopes(granted))


# --- Outbound URLs (D34) ------------------------------------------------------

GOOGLE_API_DOMAIN = ".googleapis.com"

_DEFAULT_PORTS = {"http": 80, "https": 443}


def _host(url: httpx2.URL) -> str:
    # The ASCII (punycode) host, as resolved and connected to.
    return url.raw_host.decode("ascii").lower()


def _origin(url: httpx2.URL) -> tuple[str, str, int | None]:
    return (url.scheme, _host(url), url.port or _DEFAULT_PORTS.get(url.scheme))


def configured_origins(datasette: Datasette) -> set[tuple[str, str, int | None]]:
    """``(scheme, host, port)`` of every configured ``google_base_urls``
    entry: Google's own by default, the mock's in tests."""
    urls = get_config(datasette).google_base_urls.model_dump().values()
    return {_origin(httpx2.URL(url)) for url in urls}


def check_request_url(datasette: Datasette, url: str | httpx2.URL) -> httpx2.URL:
    """``url`` parsed, if ``Credential.request()`` may send a bearer token to
    it; else ``DisallowedHost`` (D34).

    Allowed: ``https://`` on ``*.googleapis.com``, or exactly the origin
    (scheme, host, port) of a configured ``google_base_urls`` entry. Never a
    URL with userinfo (``https://evil.com@sheets.googleapis.com`` goes to
    Google, but is always a mistake or a trick).
    """
    try:
        parsed = httpx2.URL(url)
    except (httpx2.InvalidURL, TypeError):
        raise DisallowedHost("that URL", None, "it is not a valid URL") from None
    host = _host(parsed) or None
    origin = f"{parsed.scheme}://{host}" if parsed.scheme and host else "that URL"
    if host is None:
        raise DisallowedHost(origin, None, "it has no host")
    if parsed.userinfo:
        raise DisallowedHost(origin, host, "it contains a username or password")
    if _origin(parsed) in configured_origins(datasette):
        return parsed
    if parsed.scheme != "https":
        raise DisallowedHost(origin, host, "only https:// is allowed")
    if not host.endswith(GOOGLE_API_DOMAIN):
        raise DisallowedHost(origin, host, "it is not a Google API host")
    return parsed


# --- Access -------------------------------------------------------------------


def _actor_id(actor: Actor) -> str | None:
    if not actor or actor.get("id") is None:
        return None
    return str(actor["id"])


def _reconnect_url(datasette: Datasette) -> str | None:
    """Where the owner can reconnect, or None if Connect Google isn't set up."""
    if not oauth_configured(get_config(datasette)):
        return None
    return connect_url(datasette)


async def _can_use(
    datasette: Datasette, actor: Actor, row: CredentialRow | None
) -> bool:
    """May the actor use ``row`` (None for an unknown id)? Anyone but an OAuth
    credential's owner gets the same service-account check, against a decoy
    id when ``row`` isn't a service account, so an unknown id costs the same
    as an invisible one (ticket 24)."""
    actor_id = _actor_id(actor)
    if actor_id is None:
        return False
    if row is not None and row.type == OAUTH and row.owner_id == actor_id:
        # Hard-coded owner check: never datasette.allowed() for OAuth (D6).
        return True
    return await sa_allowed_or_decoy(datasette, SA_USE, actor, row)


async def _authorize(
    datasette: Datasette, credential_id: str, actor: Actor, scopes: list[str]
) -> CredentialRow:
    """Re-read the row and check the actor may use it for ``scopes`` right now.

    Raises ``CredentialNotFound``, ``CredentialForbidden``,
    ``CredentialBroken`` or ``MissingScopes``, in that order of precedence.
    """
    # TODO(D2): a later `system=True` mode (background jobs, no actor) goes here.
    row = await InternalDB(datasette.get_internal_database()).get(credential_id)
    if _actor_id(actor) is None:
        raise CredentialNotFound(credential_id)
    # An unknown id runs the same checks as an invisible one (ticket 24).
    usable = await _can_use(datasette, actor, row)
    if row is None or not usable:
        # Admins can already list every credential (ticket 15), so telling
        # them "forbidden" leaks nothing; everyone else can't tell it exists.
        if await can_admin(datasette, actor) and row is not None:
            raise CredentialForbidden("You can't use this credential")
        raise CredentialNotFound(credential_id)

    if row.status == "broken":
        raise CredentialBroken(
            row.status_detail or "marked broken",
            credential_id=row.id,
            # Only the owner gets here for OAuth; service accounts need a new
            # key (rotate), not a reconnect.
            reconnect_url=_reconnect_url(datasette) if row.type == OAUTH else None,
        )

    if row.type == OAUTH:
        missing = missing_scopes(scopes, row.scopes)
        if missing:
            # Connect always asks for the configured scope set (D4), so a plain
            # reconnect fixes anything in it; nothing else can be fixed by the
            # user.
            not_configured = missing_scopes(missing, get_config(datasette).scopes)
            raise MissingScopes(
                missing,
                reconnect_url=None if not_configured else _reconnect_url(datasette),
                not_configured=not_configured,
            )
    elif not scopes:
        # Service accounts mint exactly the scopes asked for.
        raise ValueError("scopes is required to use a service account")
    return row


# --- Tokens -------------------------------------------------------------------


async def _service_account_token(
    datasette: Datasette, row: CredentialRow, scopes: list[str], actor_id: str
) -> Token:
    """Mint a token for a service account. On ``invalid_grant`` mark the row
    broken (compare-and-swap on the key that was rejected, which evicts the
    cache and fires the broken event) and raise ``CredentialBroken``."""
    secret = await decrypt_credential(datasette, row)
    key = ServiceAccountKey.from_secret(secret, client_id=row.google_subject)
    try:
        return await mint_service_account_token(datasette, key, scopes)
    except CredentialBroken:
        if not await mark_broken(datasette, row, SA_BROKEN_DETAIL, actor_id=actor_id):
            # The key was rotated (or the row deleted) meanwhile: the rejected
            # key is no longer stored, so don't break the row. Trying again
            # re-reads it.
            raise CredentialChanged(row.id) from None
        raise CredentialBroken(SA_BROKEN_DETAIL, credential_id=row.id) from None


async def _token_for_row(
    datasette: Datasette, row: CredentialRow, scopes: list[str], actor_id: str
) -> tuple[Token, bool]:
    """Through the token cache: ``(token, hit)``, where ``hit`` is False if
    it had to be fetched. Only call with a row ``_authorize`` returned."""
    cache = get_token_cache(datasette)
    fetched = False
    if row.type == OAUTH:

        async def fetch_oauth() -> Token:
            nonlocal fetched
            fetched = True
            return await fetch_oauth_token(datasette, row, actor_id=actor_id)

        # OAuth tokens carry the granted scopes, whatever was asked for.
        token = await cache.get_or_fetch(oauth_cache_key(row), fetch_oauth)
    else:
        requested = sorted(set(scopes))

        async def fetch_service_account() -> Token:
            nonlocal fetched
            fetched = True
            return await _service_account_token(datasette, row, requested, actor_id)

        token = await cache.get_or_fetch(
            CacheKey.for_row(row, requested), fetch_service_account
        )
    record_cache_lookup(row.type, hit=not fetched)
    return token, not fetched


class TouchThrottle:
    """Decides when ``last_used_*`` is worth writing: at most once per
    credential per ``interval`` seconds, per process."""

    def __init__(
        self,
        *,
        interval: float = TOUCH_INTERVAL,
        clock: Callable[[], float] = time.monotonic,
    ):
        self.interval = interval
        self.clock = clock
        self._last: dict[str, float] = {}

    def due(self, credential_id: str) -> bool:
        """True (and recorded as touched now) if a write is due."""
        now = self.clock()
        last = self._last.get(credential_id)
        if last is not None and now - last < self.interval:
            return False
        self._last[credential_id] = now
        return True


def get_touch_throttle(datasette: Datasette) -> TouchThrottle:
    throttle = getattr(datasette, _TOUCH_ATTR, None)
    if throttle is None:
        throttle = TouchThrottle()
        setattr(datasette, _TOUCH_ATTR, throttle)
    return throttle


async def _touch_used(datasette: Datasette, credential_id: str, actor_id: str) -> None:
    if get_touch_throttle(datasette).due(credential_id):
        await InternalDB(datasette.get_internal_database()).touch_used(
            credential_id, actor_id
        )


# --- Public API ---------------------------------------------------------------


class Credential:
    """A credential the actor may use, from ``get_credential``.

    Every ``token()`` / ``request()`` re-checks access against the database
    first, so holding one across calls never outlives a revocation.
    """

    info: CredentialInfo
    """The secret-free description, as of the last access check."""

    def __init__(
        self,
        datasette: Datasette,
        info: CredentialInfo,
        *,
        actor: dict[str, Any],
        scopes: list[str],
    ):
        self._datasette = datasette
        self._actor = actor
        self._scopes = list(scopes)
        self.info = info

    @property
    def id(self) -> str:
        return self.info.id

    def __repr__(self) -> str:
        return f"<Credential {self.info.id} {self.info.type} {self.info.label!r}>"

    async def token(self) -> str:
        """A Google access token for the requested scopes.

        Re-reads the credential and re-checks access (D16), then serves from
        the in-memory cache or mints / refreshes. Raises as ``get_credential``
        does, plus ``CredentialBroken`` if Google rejects the key or grant
        (the credential is then marked broken), ``GoogleTokenError``,
        ``EncryptionNotConfigured``, ``CredentialUndecryptable`` or
        ``CredentialChanged``.

        Never log or return the token to a browser.
        """
        with credential_span(TOKEN, self.id) as span:
            row = await _authorize(self._datasette, self.id, self._actor, self._scopes)
            if span.is_recording():
                span.set_attribute(CREDENTIAL_TYPE, row.type)
            self.info = CredentialInfo.from_row(row, self._actor)
            actor_id = _actor_id(self._actor)
            assert actor_id is not None  # _authorize rejects anonymous actors
            token, hit = await _token_for_row(
                self._datasette, row, self._scopes, actor_id
            )
            if span.is_recording():
                span.set_attribute(CACHE, "hit" if hit else "miss")
            await _touch_used(self._datasette, row.id, actor_id)
            return token.access_token

    async def request(
        self,
        method: str,
        url: str | httpx2.URL,
        *,
        allow_any_host: bool = False,
        **kwargs: Any,
    ) -> httpx2.Response:
        """Make an authenticated request to a Google API.

        ``url`` must be ``https://`` on a ``*.googleapis.com`` host (or on the
        origin of a configured ``google_base_urls`` entry), with no userinfo;
        anything else raises ``DisallowedHost`` before a token is fetched or
        anything is sent (D34). ``allow_any_host=True`` skips that check: the
        bearer token then goes wherever ``url`` points.

        ``kwargs`` go to ``httpx2.AsyncClient.request`` (``params``, ``json``,
        ``headers``, ...); any ``Authorization`` header is replaced. On a 401
        the cached token is evicted and the request retried once with a fresh
        token, so a request body must be replayable (not a stream). The
        response is returned whatever its status. Uses this plugin's own
        client (no redirects followed), never the caller's.
        """
        headers = httpx2.Headers(kwargs.pop("headers", None))
        with request_call(self.id, self.info.type, method, str(url)) as call:
            # Parsed once, by the same parser the client sends with, so the
            # host checked is the host the token goes to.
            target = (
                httpx2.URL(url)
                if allow_any_host
                else check_request_url(self._datasette, url)
            )
            async with client(self._datasette) as http:
                headers["Authorization"] = f"Bearer {await self.token()}"
                response = await http.request(method, target, headers=headers, **kwargs)
                call.status = response.status_code
                if response.status_code != 401:
                    return response
                call.retried = True
                get_token_cache(self._datasette).evict(self.id)
                headers["Authorization"] = f"Bearer {await self.token()}"
                response = await http.request(method, target, headers=headers, **kwargs)
                call.status = response.status_code
                return response


async def list_credentials(
    datasette: Datasette,
    *,
    actor: dict[str, Any] | None,
    scopes: list[str] | None = None,
) -> list[CredentialInfo]:
    """The credentials ``actor`` may use: their own OAuth connections, then
    the service accounts shared with them, each oldest first.

    With ``scopes``, OAuth credentials must have been granted all of them
    (or a broader scope that implies one, D27); service accounts always qualify (they mint any scope, though the target
    file must still be shared with them, which only a request can tell).
    Broken credentials are included, with their ``status``, so a picker can
    offer "Reconnect". Anonymous actors get ``[]``. ``google-credentials-admin``
    doesn't widen this list.
    """
    actor_id = _actor_id(actor)
    if actor_id is None:
        return []
    idb = InternalDB(datasette.get_internal_database())
    owned = [row for row in await idb.list_owned(actor_id) if row.type == OAUTH]
    if scopes:
        owned = [row for row in owned if not missing_scopes(scopes, row.scopes)]
    shared = [
        row
        for row in await idb.list_by_ids(await usable_sa_ids(datasette, actor))
        if row.type == SERVICE_ACCOUNT
    ]
    return [CredentialInfo.from_row(row, actor) for row in owned + shared]


async def get_credential(
    datasette: Datasette,
    credential_id: str,
    *,
    actor: dict[str, Any] | None,
    scopes: list[str],
) -> Credential:
    """A usable credential for ``scopes``, checked against the database now.

    Raises ``CredentialNotFound`` (missing, or not the actor's to know about;
    also for anonymous actors), ``CredentialForbidden`` (visible to an admin
    but not usable), ``CredentialBroken`` (``reconnect_url`` set for OAuth)
    or ``MissingScopes`` (OAuth only). ``scopes`` must be non-empty for a
    service account (``ValueError``).
    """
    row = await _authorize(datasette, credential_id, actor, scopes)
    assert actor is not None  # _authorize rejects anonymous actors
    return Credential(
        datasette, CredentialInfo.from_row(row, actor), actor=actor, scopes=scopes
    )
