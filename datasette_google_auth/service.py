"""The credential lifecycle: rename, rotate, reconnect, delete (D13, D16).

The HTTP routes (ticket 12) call this module, never ``InternalDB`` directly.
Every function takes the acting ``actor`` and checks it first:

=====================  ==============================  =====================================
                       OAuth (``google_oauth``)        Service account
=====================  ==============================  =====================================
``rename``             owner                           ``google-service-account-edit``
``rotate_...key``      n/a                             ``google-service-account-edit``
``reconnect_url``      owner                           n/a
``delete``             owner or ``google-auth-admin``  ``-manage`` or ``google-auth-admin``
=====================  ==============================  =====================================

``google-auth-admin`` may delete anything but never rename or use someone
else's credential (D6): the admin view is list, revoke (= delete) and
delete (D13).

Errors follow the broker's no-probing rule (D23, D25): an unknown id, or
one the actor can't see, raises ``CredentialNotFound``; one they can see
but not change raises ``CredentialForbidden``. An actor "sees" a service
account they may use, and an admin sees everything.

Events (``events.py``) fire for created, reconnected, rotated, deleted and
broken; none carries a secret.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from urllib.parse import urlencode

from .broker import list_credentials, missing_scopes
from .config import REQUIRED_SCOPES, get_config
from .crypto import decrypt_credential
from .errors import (
    CredentialForbidden,
    CredentialNotFound,
    CredentialUndecryptable,
    EncryptionNotConfigured,
    InvalidLabel,
)
from .events import CredentialDeletedEvent, mark_broken, track_credential_event
from .internal_db import CredentialRow, InternalDB
from .models import CredentialInfo, DeleteResult, ListedCredential
from .oauth import DEFAULT_RETURN_TO, connect_url, revoke_token
from .permissions import (
    SA_EDIT,
    SA_MANAGE,
    can_admin,
    can_edit_sa,
    can_manage_sa,
    can_use_sa,
    sa_access,
    sa_role,
)
from .service_account import add_service_account, rotate_service_account_key
from .token_cache import get_token_cache

if TYPE_CHECKING:
    from datasette.app import Datasette

__all__ = [
    "DeleteResult",
    "add_service_account",
    "cloud_console_url",
    "delete",
    "list_with_access",
    "mark_broken",
    "reconnect_url",
    "rename",
    "rotate_service_account_key",
]

OAUTH = "google_oauth"
SERVICE_ACCOUNT = "service_account"

MAX_LABEL_LENGTH = 200

# The base URL is from Google's docs
# (https://docs.cloud.google.com/iam/docs/keys-create-delete). UNVERIFIED:
# the ``?project=`` parameter cloud_console_url() adds; check it against the
# live Cloud console before release.
CLOUD_CONSOLE_SERVICE_ACCOUNTS = (
    "https://console.cloud.google.com/iam-admin/serviceaccounts"
)

Actor = dict[str, Any] | None


def _actor_id(actor: Actor) -> str | None:
    if not actor or actor.get("id") is None:
        return None
    return str(actor["id"])


async def _load(
    datasette: Datasette, actor: Actor, credential_id: str
) -> tuple[CredentialRow, str]:
    """The row and the actor's id; ``CredentialNotFound`` for an unknown id or
    an anonymous actor."""
    row = await InternalDB(datasette.get_internal_database()).get(credential_id)
    actor_id = _actor_id(actor)
    if row is None or actor_id is None:
        raise CredentialNotFound(credential_id)
    return row, actor_id


async def _deny(
    datasette: Datasette, actor: Actor, row: CredentialRow, message: str
) -> CredentialForbidden | CredentialNotFound:
    """Forbidden if the actor can see ``row`` (admin, or a service account
    they may use), otherwise NotFound. Never ``allowed()`` for OAuth (D6)."""
    if await can_admin(datasette, actor) or await can_use_sa(datasette, actor, row):
        return CredentialForbidden(message)
    return CredentialNotFound(row.id)


def clean_label(label: str) -> str:
    """``label`` stripped; ``InvalidLabel`` if empty or too long."""
    label = label.strip()
    if not label:
        raise InvalidLabel("Label can't be empty")
    if len(label) > MAX_LABEL_LENGTH:
        raise InvalidLabel(f"Label can't be longer than {MAX_LABEL_LENGTH} characters")
    return label


def cloud_console_url(project_id: str) -> str:
    """The Cloud console's service-accounts page for a project (the
    ``?project=`` parameter is UNVERIFIED, see ``CLOUD_CONSOLE_SERVICE_ACCOUNTS``)."""
    return CLOUD_CONSOLE_SERVICE_ACCOUNTS + "?" + urlencode({"project": project_id})


# --- List ---------------------------------------------------------------------


async def list_with_access(
    datasette: Datasette, actor: Actor, scopes: list[str] | None = None
) -> list[ListedCredential]:
    """``list_credentials()``, each item with the actor's role, what they may
    change, when it was last used and (OAuth) which configured scopes it
    lacks. For ``GET /api/credentials`` and the management page.

    Visibility is exactly ``list_credentials()``'s; this only re-reads those
    rows (the broker's ``CredentialInfo`` has no ``last_used_at``) and adds
    one ``allowed_many()`` per service account. A row deleted in between is
    dropped.
    """
    infos = await list_credentials(datasette, actor=actor, scopes=scopes)
    idb = InternalDB(datasette.get_internal_database())
    rows = {row.id: row for row in await idb.list_by_ids([i.id for i in infos])}
    configured = [
        scope for scope in get_config(datasette).scopes if scope not in REQUIRED_SCOPES
    ]
    listed = []
    for info in infos:
        row = rows.get(info.id)
        if row is None:
            continue
        # From the re-read row, so every field describes the same moment.
        base = CredentialInfo.from_row(row, actor).model_dump()
        if row.type == OAUTH:
            # list_credentials only lists the actor's own OAuth credentials.
            listed.append(
                ListedCredential(
                    **base,
                    role=None,
                    can_edit=info.is_owner,
                    can_manage=info.is_owner,
                    last_used_at=row.last_used_at,
                    missing_scopes=missing_scopes(configured, row.scopes),
                )
            )
        else:
            access = await sa_access(datasette, actor, row)
            listed.append(
                ListedCredential(
                    **base,
                    role=sa_role(access),
                    can_edit=access[SA_EDIT],
                    can_manage=access[SA_MANAGE],
                    last_used_at=row.last_used_at,
                    missing_scopes=[],
                )
            )
    return listed


# --- Rename -------------------------------------------------------------------


async def rename(
    datasette: Datasette, actor: Actor, credential_id: str, label: str
) -> CredentialInfo:
    """Change a credential's label.

    OAuth: the owner only (``google-auth-admin`` gets ``CredentialForbidden``).
    Service account: ``google-service-account-edit``. Raises
    ``CredentialNotFound``, ``CredentialForbidden`` or ``InvalidLabel``.
    Fires no event.
    """
    row, actor_id = await _load(datasette, actor, credential_id)
    if row.type == OAUTH:
        allowed = row.owner_id == actor_id
    else:
        allowed = await can_edit_sa(datasette, actor, row)
    if not allowed:
        raise await _deny(
            datasette, actor, row, "You don't have permission to rename this credential"
        )
    label = clean_label(label)
    idb = InternalDB(datasette.get_internal_database())
    if not await idb.rename(row.id, label, actor_id=actor_id):
        raise CredentialNotFound(credential_id)
    updated = await idb.get(row.id)
    if updated is None:
        raise CredentialNotFound(credential_id)
    return CredentialInfo.from_row(updated, actor)


# --- Reconnect ----------------------------------------------------------------


async def reconnect_url(datasette: Datasette, actor: Actor, credential_id: str) -> str:
    """Where the owner of an OAuth credential goes to reconnect it.

    A reconnect is just a new connect: the callback's upsert on (owner,
    Google ``sub``) updates this row in place (D9), as long as the user picks
    the same Google account. Raises ``CredentialNotFound`` for anything but
    the actor's own OAuth credential (``CredentialForbidden`` for an admin).
    """
    row, actor_id = await _load(datasette, actor, credential_id)
    if row.type != OAUTH:
        raise CredentialNotFound(credential_id)
    if row.owner_id != actor_id:
        raise await _deny(
            datasette, actor, row, "Only the owner can reconnect a Google account"
        )
    return connect_url(datasette, return_to=datasette.urls.path(DEFAULT_RETURN_TO))


# --- Delete -------------------------------------------------------------------


async def delete(
    datasette: Datasette, actor: Actor, credential_id: str
) -> DeleteResult:
    """Delete a credential (D16).

    Who: OAuth, the owner or ``google-auth-admin``; service account,
    ``google-service-account-manage`` or ``google-auth-admin``. Raises
    ``CredentialNotFound`` or ``CredentialForbidden`` otherwise.

    OAuth: the refresh token is revoked at Google first, best effort; the row
    is deleted **whatever the result**, which ``DeleteResult.revoked`` /
    ``revoke_error`` report. Service account: the result names the key
    (``private_key_id``, ``project_id``) the user should delete in the Cloud
    console, since it keeps working at Google until they do.

    Either way the token cache is evicted and the deleted event fired.
    """
    row, _ = await _load(datasette, actor, credential_id)
    if row.type == OAUTH:
        allowed = row.owner_id == _actor_id(actor) or await can_admin(datasette, actor)
    else:
        allowed = await can_manage_sa(datasette, actor, row) or await can_admin(
            datasette, actor
        )
    if not allowed:
        raise await _deny(
            datasette, actor, row, "You don't have permission to delete this credential"
        )

    if row.type == OAUTH:
        result = await _revoke(datasette, row)
    else:
        result = await _service_account_result(datasette, row)

    # acl grants on a deleted service account are left in place: ULIDs are
    # never reused, so they can't apply to anything else, and datasette-acl
    # has no delete-resource API (see wiki/90-future-ideas.md).
    deleted = await InternalDB(datasette.get_internal_database()).delete(row.id)
    get_token_cache(datasette).evict(row.id)
    if not deleted:
        # Deleted concurrently; whoever did it fired the event.
        raise CredentialNotFound(credential_id)
    await track_credential_event(
        datasette, CredentialDeletedEvent, row, actor, revoked=result.revoked
    )
    return result


async def _revoke(datasette: Datasette, row: CredentialRow) -> DeleteResult:
    try:
        secret = await decrypt_credential(datasette, row)
    except (EncryptionNotConfigured, CredentialUndecryptable) as ex:
        return DeleteResult(
            id=row.id, type=row.type, revoked=False, revoke_error=str(ex)
        )
    refresh_token = secret.get("refresh_token")
    if not isinstance(refresh_token, str) or not refresh_token:
        return DeleteResult(
            id=row.id,
            type=row.type,
            revoked=False,
            revoke_error="no refresh token stored",
        )
    error = await revoke_token(datasette, refresh_token)
    return DeleteResult(
        id=row.id, type=row.type, revoked=error is None, revoke_error=error
    )


async def _service_account_result(
    datasette: Datasette, row: CredentialRow
) -> DeleteResult:
    result = DeleteResult(id=row.id, type=row.type, client_email=row.google_email)
    try:
        secret = await decrypt_credential(datasette, row)
    except (EncryptionNotConfigured, CredentialUndecryptable):
        # Still deletable; the UI just can't name the key.
        return result
    private_key_id = secret.get("private_key_id")
    project_id = secret.get("project_id")
    return result.model_copy(
        update={
            "private_key_id": private_key_id
            if isinstance(private_key_id, str)
            else None,
            "project_id": project_id if isinstance(project_id, str) else None,
            "cloud_console_url": cloud_console_url(project_id)
            if isinstance(project_id, str) and project_id
            else None,
        }
    )
