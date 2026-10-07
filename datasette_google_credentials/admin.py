"""The ``google-credentials-admin`` view of every credential (D6, D13, ticket 15).

Listing only. Admins delete through ``service.delete()``, which already lets
them; nothing here hands out a ``Credential`` or a token, and
``broker.list_credentials()`` is not widened for admins.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from typing import TYPE_CHECKING, Any

from .errors import CredentialForbidden
from .internal_db import InternalDB
from .models import AdminCredentialInfo
from .permissions import can_admin

if TYPE_CHECKING:
    from datasette.app import Datasette

logger = logging.getLogger(__name__)

#: Actor keys that may hold a display name, best first: datasette-user-profiles'
#: ``display_name``, then core's ``display_actor()`` order.
_NAME_KEYS = ("display_name", "display", "name", "username", "login")


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
    unless the actor holds ``google-credentials-admin``."""
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


def actor_ids(credentials: Iterable[AdminCredentialInfo]) -> list[str]:
    """Every actor id the admin view shows: owners, creators, last users."""
    ids = {
        actor_id
        for c in credentials
        for actor_id in (c.owner_id, c.created_by, c.last_used_by)
        if actor_id
    }
    return sorted(ids)


async def actor_names(datasette: Datasette, ids: list[str]) -> dict[str, str]:
    """Display names for actor ids, via core ``datasette.actors_from_ids()``
    (backed by whichever plugin implements that hook, e.g. datasette-accounts).
    Only ids that resolve to a name other than the id itself are included; the
    UI shows the raw id for the rest. A failing identity plugin must not block
    offboarding, so any error there means "no names"."""
    if not ids:
        return {}
    try:
        actors = await datasette.actors_from_ids(ids) or {}
    except Exception:
        logger.warning(
            "datasette-google-credentials: actors_from_ids failed; showing actor ids",
            exc_info=True,
        )
        return {}
    names = {}
    for key, actor in actors.items():
        if not isinstance(actor, dict):
            continue
        for name_key in _NAME_KEYS:
            name = actor.get(name_key)
            if isinstance(name, str) and name.strip():
                if name != str(key):
                    names[str(key)] = name
                break
    return names
