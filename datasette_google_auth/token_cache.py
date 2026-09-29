"""In-memory, per-process access-token cache (D7).

INVARIANT (D16): the cache is only consulted AFTER the caller has re-read the
credential row from the internal DB and re-checked the actor's permission for
it. A cache hit is never evidence that the actor may use the credential, and
the cache never reads the row itself. That is what makes delete / revoke /
unshare take effect immediately, even across processes.

Access tokens are never persisted, logged or returned in errors. A ``Token``
hides ``access_token`` from its ``repr``; ``CacheKey`` holds no secret.

- Keyed by ``CacheKey(credential_id, secret_version, scopes)``. Build keys with
  ``CacheKey.for_row()``: the secret version is the row's ``updated_at``
  (falling back to ``created_at``), which every secret-changing write bumps
  (``InternalDB.update_secret`` / ``upsert_oauth``), so a rotated key or a
  reconnected account misses. Lazy encryption-key re-encryption doesn't bump
  it (D20): same secret, same token.
- A token is reused while ``expires_at - now > EXPIRY_SKEW`` (60s).
- One ``asyncio.Lock`` per key: N concurrent callers make one fetch.
- A failed fetch is not cached; the next caller retries.
- At most ``max_entries`` keys (LRU), so a long-running process can't grow
  without bound.
"""

from __future__ import annotations

import asyncio
import time
from collections import OrderedDict
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from .tokens import Token

if TYPE_CHECKING:
    from collections.abc import Iterable

    from datasette.app import Datasette

    from .internal_db import CredentialRow

# A cached token is reused only while it has more than this left (seconds),
# as sqlite-google-sheets' `EXPIRY_SKEW`.
EXPIRY_SKEW = 60.0
DEFAULT_MAX_ENTRIES = 1000

_ATTR = "_google_auth_tokens"


@dataclass(frozen=True)
class CacheKey:
    credential_id: str
    # Changes whenever the stored secret does, so rotation invalidates.
    secret_version: str
    # Service accounts mint per requested scope set; OAuth tokens carry the
    # granted scopes.
    scopes: frozenset[str]

    @classmethod
    def for_row(cls, row: CredentialRow, scopes: Iterable[str]) -> CacheKey:
        """The key for a freshly re-read row and a scope set."""
        return cls(
            credential_id=row.id,
            secret_version=row.updated_at or row.created_at,
            scopes=frozenset(scopes),
        )


@dataclass
class _Entry:
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    token: Token | None = None


class TokenCache:
    def __init__(
        self,
        *,
        clock: Callable[[], float] = time.time,
        max_entries: int = DEFAULT_MAX_ENTRIES,
    ):
        """``clock`` returns Unix epoch seconds, like ``Token.expires_at``."""
        if max_entries < 1:
            raise ValueError("max_entries must be at least 1")
        self.clock = clock
        self.max_entries = max_entries
        self._entries: OrderedDict[CacheKey, _Entry] = OrderedDict()

    def __len__(self) -> int:
        return len(self._entries)

    def _is_fresh(self, token: Token) -> bool:
        return token.expires_at - self.clock() > EXPIRY_SKEW

    def _entry(self, key: CacheKey) -> _Entry:
        entry = self._entries.get(key)
        if entry is None:
            entry = _Entry()
            self._entries[key] = entry
            while len(self._entries) > self.max_entries:
                # Dropping an entry mid-fetch is safe: that fetch completes
                # into the orphaned entry and its waiters still get the token.
                self._entries.popitem(last=False)
        else:
            self._entries.move_to_end(key)
        return entry

    async def get_or_fetch(
        self, key: CacheKey, fetch: Callable[[], Awaitable[Token]]
    ) -> Token:
        """A fresh cached token for ``key``, or the result of ``fetch()``.

        Only call this after re-reading the row and re-checking permission
        (see the module docstring). Exceptions from ``fetch`` propagate and
        nothing is cached.
        """
        entry = self._entry(key)
        token = entry.token
        if token is not None and self._is_fresh(token):
            return token
        async with entry.lock:
            # Another caller may have fetched while we waited for the lock.
            token = entry.token
            if token is not None and self._is_fresh(token):
                return token
            token = await fetch()
            entry.token = token
            return token

    def evict(self, credential_id: str) -> None:
        """Drop every cached token (all scope sets and secret versions) for a
        credential. Call on delete, disconnect or revocation (D16).

        An in-flight fetch for that credential finishes into a detached entry,
        so its result is never cached.
        """
        for key in [k for k in self._entries if k.credential_id == credential_id]:
            del self._entries[key]


def get_token_cache(datasette: Datasette) -> TokenCache:
    """This instance's token cache (created in ``startup``; created now if
    startup hasn't run)."""
    cache = getattr(datasette, _ATTR, None)
    if cache is None:
        cache = TokenCache()
        setattr(datasette, _ATTR, cache)
    return cache
