"""Datasette events for the credential lifecycle (D10).

Registered with the ``register_events`` hook and fired with
``datasette.track_event()``, so any plugin implementing ``track_event``
(audit logs, alerts, telemetry) sees them:

* ``google-credential-created``: a service account was added, or a
  Google account connected for the first time
* ``google-credential-reconnected``: an existing OAuth credential was
  connected again (new refresh token, same row)
* ``google-credential-rotated``: a service account got a new key
* ``google-credential-deleted``: with ``revoked`` for OAuth
* ``google-credential-broken``: Google rejected the stored secret
  (``invalid_grant``), with the ``detail`` users see

There are no per-use events (D10): ``last_used_*`` covers that.

**No event carries a secret.** Every field is copied from the plaintext
columns of the row (id, type, owner, Google email) or is a fixed message;
nothing here ever sees a decrypted secret or a token.

``mark_broken`` lives here rather than in ``service.py`` because the broker
and the OAuth refresh path need it, and ``service.py`` imports both.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from datasette.events import Event

from .internal_db import CredentialRow, InternalDB
from .telemetry import record_broken
from .token_cache import get_token_cache

if TYPE_CHECKING:
    from datasette.app import Datasette


@dataclass
class CredentialEvent(Event):
    """Fields shared by every credential event (not registered itself).

    :ivar credential_id: The credential's id (a ULID).
    :ivar credential_type: ``google_oauth`` or ``service_account``.
    :ivar owner_id: The actor id that owns (OAuth) or created (service
        account) the credential. Differs from ``actor`` when an admin acts.
    :ivar google_email: The Google account, or the service account's
        ``client_email``.
    """

    credential_id: str
    credential_type: str
    owner_id: str
    google_email: str | None


@dataclass
class CredentialCreatedEvent(CredentialEvent):
    """Event name: ``google-credential-created``"""

    name = "google-credential-created"


@dataclass
class CredentialReconnectedEvent(CredentialEvent):
    """Event name: ``google-credential-reconnected``"""

    name = "google-credential-reconnected"


@dataclass
class CredentialRotatedEvent(CredentialEvent):
    """Event name: ``google-credential-rotated``"""

    name = "google-credential-rotated"


@dataclass
class CredentialDeletedEvent(CredentialEvent):
    """Event name: ``google-credential-deleted``

    :ivar revoked: OAuth: whether Google confirmed the revocation. ``None``
        for service accounts, which have nothing to revoke from here.
    """

    name = "google-credential-deleted"
    revoked: bool | None


@dataclass
class CredentialBrokenEvent(CredentialEvent):
    """Event name: ``google-credential-broken``

    :ivar detail: The status detail shown to users (no secrets).
    """

    name = "google-credential-broken"
    detail: str


EVENTS: list[type[Event]] = [
    CredentialCreatedEvent,
    CredentialReconnectedEvent,
    CredentialRotatedEvent,
    CredentialDeletedEvent,
    CredentialBrokenEvent,
]


async def track_credential_event(
    datasette: Datasette,
    event_class: type[CredentialEvent],
    row: CredentialRow,
    actor: dict[str, Any] | None,
    **extra: Any,
) -> None:
    """Fire ``event_class`` for ``row``. Only the row's plaintext columns go
    into the event."""
    await datasette.track_event(
        event_class(
            actor=actor,
            credential_id=row.id,
            credential_type=row.type,
            owner_id=row.owner_id,
            google_email=row.google_email,
            **extra,
        )
    )


async def mark_broken(
    datasette: Datasette,
    row: CredentialRow,
    detail: str,
    *,
    actor_id: str | None = None,
) -> bool:
    """Mark ``row`` broken, if it still holds the secret Google rejected.

    A compare-and-swap on ``row.secret_encrypted`` (D24): a reconnect or key
    rotation since ``row`` was read wins, and nothing happens. Only when the
    write lands are the cached tokens evicted and the broken event fired.
    Returns whether it landed. ``detail`` is shown to users: never put a
    token or key in it.
    """
    idb = InternalDB(datasette.get_internal_database())
    if not await idb.mark_broken(row.id, detail, expected_secret=row.secret_encrypted):
        return False
    get_token_cache(datasette).evict(row.id)
    record_broken(row.type)
    await track_credential_event(
        datasette,
        CredentialBrokenEvent,
        row,
        {"id": actor_id} if actor_id is not None else None,
        detail=detail,
    )
    return True
