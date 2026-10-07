"""The ``Token`` type shared by service-account minting, OAuth refresh and the
token cache.

``expires_at`` is wall-clock time in Unix epoch seconds (a ``float``, as from
``time.time()``). Build tokens from a token-endpoint response with
``Token.from_expires_in()`` so the default lifetime is applied in one place.

Never log or return a ``Token``'s ``access_token``: it is kept out of
``repr`` (and so ``str``) so an accidental ``print(token)`` or a logged
exception can't leak it.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

# Used when the token endpoint omits `expires_in` (as sqlite-google-sheets'
# `DEFAULT_TOKEN_LIFETIME_SECS`).
DEFAULT_TOKEN_LIFETIME = 3600.0


@dataclass(frozen=True)
class Token:
    """A Google access token.

    ``expires_at``: Unix epoch seconds. ``scopes``: the scopes the token
    carries (requested for service accounts, granted for OAuth).
    """

    access_token: str = field(repr=False)
    expires_at: float
    scopes: frozenset[str]

    @classmethod
    def from_expires_in(
        cls,
        access_token: str,
        expires_in: float | None,
        scopes: frozenset[str] | set[str] | list[str] | tuple[str, ...],
        *,
        now: float | None = None,
    ) -> Token:
        """Build a token from a token-endpoint reply.

        ``expires_in`` of ``None`` (Google omitted it) means
        ``DEFAULT_TOKEN_LIFETIME``. ``now`` defaults to ``time.time()``.
        """
        if now is None:
            now = time.time()
        lifetime = DEFAULT_TOKEN_LIFETIME if expires_in is None else float(expires_in)
        return cls(
            access_token=access_token,
            expires_at=now + lifetime,
            scopes=frozenset(scopes),
        )
