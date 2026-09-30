"""The ``google-auth-admin`` view of every credential (D6, D13, ticket 15).

Listing only. Admins delete through ``service.delete()``, which already lets
them; nothing here hands out a ``Credential`` or a token, and
``broker.list_credentials()`` is not widened for admins.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .errors import CredentialForbidden
from .internal_db import InternalDB
from .models import AdminCredentialInfo
from .permissions import can_admin

if TYPE_CHECKING:
    from datasette.app import Datasette


async def list_all_credentials(
    datasette: Datasette,
    actor: dict[str, Any] | None,
    *,
    owner: str | None = None,
    type: str | None = None,
    status: str | None = None,
) -> list[AdminCredentialInfo]:
    """Every credential, oldest first, optionally filtered by exact
    ``owner`` id, ``type`` and ``status``. Raises ``CredentialForbidden``
    unless the actor holds ``google-auth-admin``."""
    if not actor or not await can_admin(datasette, actor):
        raise CredentialForbidden("You don't have permission to list all credentials")
    rows = await InternalDB(datasette.get_internal_database()).list_all()
    return [
        AdminCredentialInfo.from_row(row, actor)
        for row in rows
        if (owner is None or row.owner_id == owner)
        and (type is None or row.type == type)
        and (status is None or row.status == status)
    ]
