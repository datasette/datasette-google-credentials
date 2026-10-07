"""The datasette-google-credentials permission model: actions, resource, acl roles (D6).

* **Global actions** (no resource), handed out through ``datasette.yaml``
  ``permissions:`` blocks: ``google-credentials-connect`` (connect your own Google
  account), ``google-credentials-add-service-account`` and ``google-credentials-admin``
  (list, revoke and delete anyone's credentials; it never grants *use* of
  someone else's OAuth credential).
* **Service accounts** are a one-level acl resource, type
  ``google-service-account``: the *parent* is the credential id, the *child*
  is always NULL. Use / edit / manage are acl grants, bundled into the
  User / Editor / Manager roles, and the creator is seeded as Manager.
* **OAuth credentials are not a resource at all.** They are owner-only and
  the broker checks ``owner_id == actor["id"]`` in code. datasette-acl has no
  grant-veto hook, so any Manager or root could write a grant row for any
  ``(type, parent)``; the defence is structural instead:
  ``ServiceAccountResource.resources_sql`` only lists ``service_account``
  rows, so ``allowed_resources`` never yields an OAuth id and acl's grant API
  404s on one (``resource_exists``). ``datasette.allowed()`` on a *single*
  resource does not consult ``resources_sql`` (a stray grant on an OAuth id
  makes it return True), so **never call** ``datasette.allowed()`` **for an
  OAuth credential**. The ``can_*_sa`` helpers enforce this: they take the
  credential row and return False, without calling ``allowed()``, unless
  ``row.type == "service_account"``.

datasette-acl is a hard dependency (D5), so every import here is
unconditional. Closest template: ``datasette-alerts/datasette_alerts/permissions.py``.
"""

from __future__ import annotations

import dataclasses

from datasette.permissions import Action, Resource
from datasette_acl.grants import Principal
from datasette_acl.grants import grant as _acl_grant
from datasette_acl.roles import AclRole, standard_roles

from .internal_db import TABLE, CredentialRow
from .models import SaRole

# --- Names ------------------------------------------------------------------

#: acl resource type for a service-account credential (1-level: the id).
RESOURCE_TYPE = "google-service-account"

CONNECT = "google-credentials-connect"
ADD_SERVICE_ACCOUNT = "google-credentials-add-service-account"
ADMIN = "google-credentials-admin"

SA_USE = "google-service-account-use"
SA_EDIT = "google-service-account-edit"
SA_MANAGE = "google-service-account-manage"

#: How many resources to pull per page out of ``allowed_resources``.
_PAGE_SIZE = 1000


# --- Resource ---------------------------------------------------------------


class ServiceAccountResource(Resource):
    """One service-account credential (resource type ``google-service-account``).

    One level: ``parent`` is the credential id, ``child`` is always NULL.
    acl's ``build_resource`` constructs a parent-only type as ``rc(parent)``,
    so the id is accepted positionally.
    """

    name = RESOURCE_TYPE
    parent_class = None

    def __init__(self, credential_id: str):
        super().__init__(parent=str(credential_id), child=None)

    @classmethod
    async def resources_sql(cls, datasette, actor=None) -> str:
        # Only service accounts. Excluding OAuth rows here is what makes a
        # stray grant on an OAuth credential's id inert (module docstring).
        return (
            f"SELECT id AS parent, NULL AS child FROM {TABLE}"
            " WHERE type = 'service_account'"
        )


# --- Actions and roles ------------------------------------------------------


def actions() -> list[Action]:
    """The six actions, for the ``register_actions`` hook.

    The three per-SA actions carry ``resource_class``, which is how acl
    discovers the resource type. ``also_requires=SA_USE`` folds the use check
    into edit and manage in core, so call sites never re-check it.
    """
    return [
        Action(
            name=CONNECT,
            abbr="gac",
            description="Can connect their own Google account",
        ),
        Action(
            name=ADD_SERVICE_ACCOUNT,
            abbr="gasa",
            description="Can add a Google service account",
        ),
        Action(
            name=ADMIN,
            abbr="gaad",
            description=(
                "Can list, revoke and delete anyone's Google credentials "
                "(never use them)"
            ),
        ),
        Action(
            name=SA_USE,
            abbr="gsau",
            description="Can use this service account to call Google APIs",
            resource_class=ServiceAccountResource,
        ),
        Action(
            name=SA_EDIT,
            abbr="gsae",
            description="Can rename this service account and rotate its key",
            resource_class=ServiceAccountResource,
            also_requires=SA_USE,
        ),
        Action(
            name=SA_MANAGE,
            abbr="gsam",
            description="Can share and delete this service account",
            resource_class=ServiceAccountResource,
            also_requires=SA_USE,
        ),
    ]


def acl_roles() -> list[AclRole]:
    """User / Editor / Manager for ``google-service-account``.

    ``standard_roles`` builds the cumulative triple (Manager carries
    ``manage=True``); its bottom role is called "Viewer", which reads wrong
    for a credential, so it is renamed to "User".
    """
    viewer, editor, manager = standard_roles(
        RESOURCE_TYPE,
        view=SA_USE,
        edit=SA_EDIT,
        manage=SA_MANAGE,
        descriptions={
            "Viewer": (
                "Can import/export with this service account; cannot see the key"
            ),
            "Editor": "Can rename and rotate the key",
            "Manager": "Can share and delete",
        },
    )
    return [dataclasses.replace(viewer, name="User"), editor, manager]


# --- Seeding ----------------------------------------------------------------


async def seed_manager(datasette, credential_id: str, actor_id: str) -> None:
    """Grant the creator of a service account the Manager role on it."""
    await _acl_grant(
        datasette,
        RESOURCE_TYPE,
        str(credential_id),
        principal=Principal.actor(str(actor_id)),
        role="Manager",
        by_actor=str(actor_id),
    )


# --- can_* ------------------------------------------------------------------
#
# The per-SA checks take the credential *row*, not a bare id: an acl grant row
# on an OAuth credential's id does make a single-resource ``allowed()`` return
# True (it never consults ``resources_sql``), so the type check lives here and
# ``datasette.allowed()`` is never reached for anything but a service account.


async def _sa_allowed(datasette, action: str, actor, row: CredentialRow) -> bool:
    if row.type != "service_account":
        return False
    return await datasette.allowed(
        action=action, resource=ServiceAccountResource(row.id), actor=actor
    )


async def can_use_sa(datasette, actor, row: CredentialRow) -> bool:
    """May the actor use this service account? False for any other type."""
    return await _sa_allowed(datasette, SA_USE, actor, row)


async def can_edit_sa(datasette, actor, row: CredentialRow) -> bool:
    """May the actor rename it or rotate its key? False for any other type."""
    return await _sa_allowed(datasette, SA_EDIT, actor, row)


async def can_manage_sa(datasette, actor, row: CredentialRow) -> bool:
    """May the actor share or delete it? False for any other type."""
    return await _sa_allowed(datasette, SA_MANAGE, actor, row)


#: A service-account id that can never exist (credential ids are 26-character
#: ULIDs), checked in place of a real one by ``sa_allowed_or_decoy``.
DECOY_SA_ID = "no-such-service-account"


async def sa_allowed_or_decoy(
    datasette, action: str, actor, row: CredentialRow | None
) -> bool:
    """``can_*_sa`` for denial paths that must cost the same whatever the id.

    For a service-account row this is ``allowed(action)`` on it. For an
    unknown id (``row`` is None) or any other type it runs the same
    ``allowed()`` against ``DECOY_SA_ID`` instead, discards the answer and
    returns False, so an unknown id, someone else's OAuth credential and an
    unshared service account do the same permission work (ticket 24). The
    OAuth credential's own id never reaches ``allowed()`` (D19).
    """
    if row is not None and row.type == "service_account":
        return await _sa_allowed(datasette, action, actor, row)
    await datasette.allowed(
        action=action, resource=ServiceAccountResource(DECOY_SA_ID), actor=actor
    )
    return False


async def sa_access(datasette, actor, row: CredentialRow) -> dict[str, bool]:
    """``{SA_USE: …, SA_EDIT: …, SA_MANAGE: …}`` for one service account, in
    one ``allowed_many()`` query (edit and manage already fold in use via
    ``also_requires``). All False for any other type, without a check."""
    names = (SA_USE, SA_EDIT, SA_MANAGE)
    if row.type != "service_account":
        return dict.fromkeys(names, False)
    return await datasette.allowed_many(
        actions=list(names), resource=ServiceAccountResource(row.id), actor=actor
    )


def sa_role(access: dict[str, bool]) -> SaRole | None:
    """The acl role name matching ``sa_access()``'s verdicts, for display.
    Permissions granted outside acl needn't nest, so gate controls on the
    verdicts themselves, not on this."""
    if access.get(SA_MANAGE):
        return "Manager"
    if access.get(SA_EDIT):
        return "Editor"
    if access.get(SA_USE):
        return "User"
    return None


async def can_connect(datasette, actor) -> bool:
    return await datasette.allowed(action=CONNECT, actor=actor)


async def can_add_service_account(datasette, actor) -> bool:
    return await datasette.allowed(action=ADD_SERVICE_ACCOUNT, actor=actor)


async def can_admin(datasette, actor) -> bool:
    return await datasette.allowed(action=ADMIN, actor=actor)


async def has_any_global_action(datasette, actor) -> bool:
    """Does a signed-in actor hold any of the three global actions? Decides
    the "Google accounts" menu link. Anonymous actors never do, even when
    config allows an action to everyone: the page 403s them."""
    if not actor or actor.get("id") is None:
        return False
    verdicts = await datasette.allowed_many(
        actions=[CONNECT, ADD_SERVICE_ACCOUNT, ADMIN], actor=actor
    )
    return any(verdicts.values())


# --- Listing ----------------------------------------------------------------


async def usable_sa_ids(datasette, actor) -> list[str]:
    """Ids of every service account the actor may use.

    One-level resource, so the id is the **parent**. Only ids listed by
    ``resources_sql`` come back, so this never includes an OAuth credential.
    """
    page = await datasette.allowed_resources(SA_USE, actor, limit=_PAGE_SIZE)
    return [r.parent async for r in page.all() if r.parent is not None]
