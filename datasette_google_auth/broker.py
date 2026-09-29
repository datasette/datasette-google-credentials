"""The consumer broker API (D11): the one place other plugins get Google
credentials and tokens from.

    creds = await list_credentials(datasette, actor=actor, scopes=[SHEETS])
    cred = await get_credential(datasette, creds[0].id, actor=actor, scopes=[SHEETS])
    response = await cred.request("GET", url)

Access rules:

* **OAuth** credentials are owner-only: ``owner_id == actor["id"]``, checked
  here in code. ``datasette.allowed()`` is never called for one (D6, D19).
* **Service accounts** need ``google-service-account-use``, via the
  type-gated ``can_use_sa``.
* Anyone who can't use a credential and couldn't see it either gets
  ``CredentialNotFound``, exactly as for an id that doesn't exist (no ID
  probing). ``CredentialForbidden`` is only for actors who can see it but not
  use it: in v0, a ``google-auth-admin`` looking at someone else's credential.

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
    MissingScopes,
)
from .http import client
from .internal_db import CredentialRow, InternalDB
from .models import CredentialInfo
from .oauth import connect_url, fetch_oauth_token, oauth_cache_key
from .permissions import can_admin, can_use_sa, usable_sa_ids
from .service_account import ServiceAccountKey, mint_service_account_token
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

_TOUCH_ATTR = "_google_auth_touch_throttle"

Actor = dict[str, Any] | None


# --- Scopes -----------------------------------------------------------------


def missing_scopes(requested: Iterable[str], granted: Iterable[str]) -> list[str]:
    """The requested scopes not covered by ``granted``, sorted.

    Strict string matching for now: ``spreadsheets`` does NOT cover
    ``spreadsheets.readonly``. Whether broader scopes imply narrower ones is
    ticket 16's open decision; change it here only.
    """
    return sorted(set(requested) - set(granted))


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


async def _can_use(datasette: Datasette, actor: Actor, row: CredentialRow) -> bool:
    actor_id = _actor_id(actor)
    if actor_id is None:
        return False
    if row.type == OAUTH:
        # Hard-coded owner check: never datasette.allowed() for OAuth (D6).
        return row.owner_id == actor_id
    if row.type == SERVICE_ACCOUNT:
        return await can_use_sa(datasette, actor, row)
    return False


async def _authorize(
    datasette: Datasette, credential_id: str, actor: Actor, scopes: list[str]
) -> CredentialRow:
    """Re-read the row and check the actor may use it for ``scopes`` right now.

    Raises ``CredentialNotFound``, ``CredentialForbidden``,
    ``CredentialBroken`` or ``MissingScopes``, in that order of precedence.
    """
    # TODO(D2): a later `system=True` mode (background jobs, no actor) goes here.
    row = await InternalDB(datasette.get_internal_database()).get(credential_id)
    if row is None or _actor_id(actor) is None:
        raise CredentialNotFound(credential_id)
    if not await _can_use(datasette, actor, row):
        # Admins can already list every credential (ticket 15), so telling
        # them "forbidden" leaks nothing; everyone else can't tell it exists.
        if await can_admin(datasette, actor):
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
    datasette: Datasette, row: CredentialRow, scopes: list[str]
) -> Token:
    """Mint a token for a service account. On ``invalid_grant`` mark the row
    broken (compare-and-swap on the key that was rejected) and raise
    ``CredentialBroken``."""
    blob = row.secret_encrypted
    secret = await decrypt_credential(datasette, row)
    key = ServiceAccountKey.from_secret(secret, client_id=row.google_subject)
    try:
        return await mint_service_account_token(datasette, key, scopes)
    except CredentialBroken:
        idb = InternalDB(datasette.get_internal_database())
        if not await idb.mark_broken(row.id, SA_BROKEN_DETAIL, expected_secret=blob):
            # The key was rotated (or the row deleted) meanwhile: the rejected
            # key is no longer stored, so don't break the row. Trying again
            # re-reads it.
            raise CredentialChanged(row.id) from None
        get_token_cache(datasette).evict(row.id)
        # Ticket 11: fire the credential-broken event here.
        raise CredentialBroken(SA_BROKEN_DETAIL, credential_id=row.id) from None


async def _token_for_row(
    datasette: Datasette, row: CredentialRow, scopes: list[str], actor_id: str
) -> Token:
    """Through the token cache. Only call with a row ``_authorize`` returned."""
    cache = get_token_cache(datasette)
    if row.type == OAUTH:

        async def fetch_oauth() -> Token:
            return await fetch_oauth_token(datasette, row, actor_id=actor_id)

        # OAuth tokens carry the granted scopes, whatever was asked for.
        return await cache.get_or_fetch(oauth_cache_key(row), fetch_oauth)

    requested = sorted(set(scopes))

    async def fetch_service_account() -> Token:
        return await _service_account_token(datasette, row, requested)

    return await cache.get_or_fetch(
        CacheKey.for_row(row, requested), fetch_service_account
    )


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
        row = await _authorize(self._datasette, self.id, self._actor, self._scopes)
        self.info = CredentialInfo.from_row(row, self._actor)
        actor_id = _actor_id(self._actor)
        assert actor_id is not None  # _authorize rejects anonymous actors
        token = await _token_for_row(self._datasette, row, self._scopes, actor_id)
        await _touch_used(self._datasette, row.id, actor_id)
        return token.access_token

    async def request(self, method: str, url: str, **kwargs: Any) -> httpx2.Response:
        """Make an authenticated request to a Google API.

        ``kwargs`` go to ``httpx2.AsyncClient.request`` (``params``, ``json``,
        ``headers``, ...); any ``Authorization`` header is replaced. On a 401
        the cached token is evicted and the request retried once with a fresh
        token, so a request body must be replayable (not a stream). The
        response is returned whatever its status. Uses this plugin's own
        client (no redirects followed), never the caller's.
        """
        # TODO(ticket 22): restrict `url` to an allowlist of Google API hosts
        # (needs Alex's decision); for now any URL gets the bearer token.
        headers = httpx2.Headers(kwargs.pop("headers", None))
        async with client(self._datasette) as http:
            headers["Authorization"] = f"Bearer {await self.token()}"
            response = await http.request(method, url, headers=headers, **kwargs)
            if response.status_code != 401:
                return response
            get_token_cache(self._datasette).evict(self.id)
            headers["Authorization"] = f"Bearer {await self.token()}"
            return await http.request(method, url, headers=headers, **kwargs)


async def list_credentials(
    datasette: Datasette,
    *,
    actor: dict[str, Any] | None,
    scopes: list[str] | None = None,
) -> list[CredentialInfo]:
    """The credentials ``actor`` may use: their own OAuth connections, then
    the service accounts shared with them, each oldest first.

    With ``scopes``, OAuth credentials must have been granted all of them;
    service accounts always qualify (they mint any scope, though the target
    file must still be shared with them, which only a request can tell).
    Broken credentials are included, with their ``status``, so a picker can
    offer "Reconnect". Anonymous actors get ``[]``. ``google-auth-admin``
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
