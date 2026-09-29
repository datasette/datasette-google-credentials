import pytest
import pytest_asyncio
from datasette.app import Datasette
from datasette_acl.grants import Principal, grant
from datasette_acl.roles import roles_for
from datasette_acl.utils import resource_exists

from datasette_google_auth.internal_db import InternalDB
from datasette_google_auth.permissions import (
    ADD_SERVICE_ACCOUNT,
    ADMIN,
    CONNECT,
    RESOURCE_TYPE,
    SA_EDIT,
    SA_MANAGE,
    SA_USE,
    ServiceAccountResource,
    can_add_service_account,
    can_admin,
    can_connect,
    can_edit_sa,
    can_manage_sa,
    can_use_sa,
    seed_manager,
    usable_sa_ids,
)

# Stand-in for a Fernet token; encryption is ticket 04.
SECRET = b"encrypted-secret"

ALICE = {"id": "alice"}
BOB = {"id": "bob"}
CAROL = {"id": "carol"}
ROOT = {"id": "root"}


async def make_datasette(config=None) -> Datasette:
    datasette = Datasette(memory=True, config=config)
    await datasette.invoke_startup()
    return datasette


@pytest_asyncio.fixture
async def datasette():
    return await make_datasette()


async def add_sa(datasette, owner_id="alice", label="SA"):
    return await InternalDB(datasette.get_internal_database()).insert(
        type="service_account",
        label=label,
        owner_id=owner_id,
        secret_encrypted=SECRET,
        created_by=owner_id,
        google_subject="1234567890",
        google_email="sa@project.iam.gserviceaccount.com",
    )


async def add_oauth(datasette, owner_id="alice"):
    row, _ = await InternalDB(datasette.get_internal_database()).upsert_oauth(
        owner_id,
        "sub-1",
        google_email="alice@example.com",
        label="alice@example.com",
        scopes=["openid", "email"],
        secret_encrypted=SECRET,
        actor_id=owner_id,
    )
    return row


async def abilities(datasette, actor, row) -> tuple[bool, bool, bool]:
    return (
        await can_use_sa(datasette, actor, row),
        await can_edit_sa(datasette, actor, row),
        await can_manage_sa(datasette, actor, row),
    )


# ------------------------------------------------------------- registration


@pytest.mark.asyncio
async def test_actions_are_registered(datasette):
    expected = {
        CONNECT: (None, None),
        ADD_SERVICE_ACCOUNT: (None, None),
        ADMIN: (None, None),
        SA_USE: (ServiceAccountResource, None),
        SA_EDIT: (ServiceAccountResource, SA_USE),
        SA_MANAGE: (ServiceAccountResource, SA_USE),
    }
    for name, (resource_class, also_requires) in expected.items():
        action = datasette.actions[name]
        assert action.resource_class is resource_class
        assert action.also_requires == also_requires
        assert action.abbr
        assert datasette.get_action(action.abbr) is action


@pytest.mark.asyncio
async def test_acl_roles_are_registered(datasette):
    roles = {role.name: role for role in roles_for(datasette, RESOURCE_TYPE)}
    assert list(roles) == ["User", "Editor", "Manager"]
    assert roles["User"].actions == [SA_USE]
    assert roles["Editor"].actions == [SA_USE, SA_EDIT]
    assert roles["Manager"].actions == [SA_USE, SA_EDIT, SA_MANAGE]
    assert [r.manage for r in roles.values()] == [False, False, True]


# ------------------------------------------------------- service-account acl


@pytest.mark.asyncio
async def test_seeded_manager_can_use_edit_and_manage(datasette):
    sa = await add_sa(datasette)
    await seed_manager(datasette, sa.id, "alice")
    assert await abilities(datasette, ALICE, sa) == (True, True, True)
    assert await abilities(datasette, BOB, sa) == (False, False, False)
    assert await abilities(datasette, None, sa) == (False, False, False)
    assert await usable_sa_ids(datasette, ALICE) == [sa.id]
    assert await usable_sa_ids(datasette, BOB) == []


@pytest.mark.asyncio
async def test_user_can_use_but_not_edit(datasette):
    sa = await add_sa(datasette)
    await seed_manager(datasette, sa.id, "alice")
    await grant(
        datasette,
        RESOURCE_TYPE,
        sa.id,
        principal=Principal.actor("bob"),
        role="User",
        by_actor="alice",
    )
    assert await abilities(datasette, BOB, sa) == (True, False, False)
    assert await usable_sa_ids(datasette, BOB) == [sa.id]


@pytest.mark.asyncio
async def test_editor_can_edit_but_not_manage(datasette):
    sa = await add_sa(datasette)
    await seed_manager(datasette, sa.id, "alice")
    await grant(
        datasette,
        RESOURCE_TYPE,
        sa.id,
        principal=Principal.actor("carol"),
        role="Editor",
        by_actor="alice",
    )
    assert await abilities(datasette, CAROL, sa) == (True, True, False)


@pytest.mark.asyncio
async def test_grants_are_per_service_account(datasette):
    sa1 = await add_sa(datasette, label="one")
    sa2 = await add_sa(datasette, label="two")
    await seed_manager(datasette, sa1.id, "alice")
    await seed_manager(datasette, sa2.id, "bob")
    assert await abilities(datasette, ALICE, sa2) == (False, False, False)
    assert await usable_sa_ids(datasette, ALICE) == [sa1.id]
    assert await usable_sa_ids(datasette, BOB) == [sa2.id]


@pytest.mark.asyncio
async def test_root_is_allowed_everything_on_service_accounts(datasette):
    datasette.root_enabled = True
    sa = await add_sa(datasette)
    await seed_manager(datasette, sa.id, "alice")
    assert await abilities(datasette, ROOT, sa) == (True, True, True)
    assert await usable_sa_ids(datasette, ROOT) == [sa.id]


# ------------------------------------------------ OAuth is never a resource


@pytest.mark.asyncio
async def test_oauth_credential_is_not_a_resource(datasette):
    sa = await add_sa(datasette)
    oauth = await add_oauth(datasette)
    # acl's grant API and admin pages 404 on anything resources_sql omits.
    assert await resource_exists(datasette, RESOURCE_TYPE, sa.id)
    assert not await resource_exists(datasette, RESOURCE_TYPE, oauth.id)


@pytest.mark.asyncio
async def test_acl_grant_on_oauth_id_is_inert(datasette):
    datasette.root_enabled = True
    sa = await add_sa(datasette)
    oauth = await add_oauth(datasette)
    # The acl grant API refuses this (above), but grant() writes the row
    # anyway: exactly the stray row the structural defence must survive.
    await grant(
        datasette,
        RESOURCE_TYPE,
        oauth.id,
        principal=Principal.actor("bob"),
        role="Manager",
        by_actor="root",
    )
    assert await usable_sa_ids(datasette, BOB) == []
    # Even root, allowed everything, only ever sees service accounts.
    assert await usable_sa_ids(datasette, ROOT) == [sa.id]


@pytest.mark.asyncio
async def test_can_sa_helpers_never_call_allowed_for_oauth(datasette, monkeypatch):
    datasette.root_enabled = True
    oauth = await add_oauth(datasette)
    await grant(
        datasette,
        RESOURCE_TYPE,
        oauth.id,
        principal=Principal.actor("bob"),
        role="Manager",
        by_actor="root",
    )
    # Core itself would say yes to the stray grant; the helpers must not ask.
    assert await datasette.allowed(
        action=SA_USE, resource=ServiceAccountResource(oauth.id), actor=BOB
    )

    calls = []
    real_allowed = datasette.allowed

    async def spy_allowed(**kwargs):
        calls.append(kwargs)
        return await real_allowed(**kwargs)

    monkeypatch.setattr(datasette, "allowed", spy_allowed)
    for actor in (BOB, ROOT, ALICE):
        assert await abilities(datasette, actor, oauth) == (False, False, False)
    assert calls == []

    # The spy does see service-account checks, so it is wired up.
    sa = await add_sa(datasette)
    await seed_manager(datasette, sa.id, "alice")
    assert await can_use_sa(datasette, ALICE, sa)
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_permissions_block_on_oauth_id_is_inert():
    # Instance-wide use for bob: covers every resource of the type, and
    # resources_sql decides what the type's resources are.
    datasette = await make_datasette(
        config={"permissions": {SA_USE: {"id": "bob"}}},
    )
    sa = await add_sa(datasette)
    await add_oauth(datasette)
    assert await usable_sa_ids(datasette, BOB) == [sa.id]
    assert await usable_sa_ids(datasette, ALICE) == []


@pytest.mark.xfail(
    reason="End-to-end check needs the broker (ticket 10)",
    raises=ImportError,
    strict=True,
)
@pytest.mark.asyncio
async def test_acl_grant_on_oauth_id_does_not_make_it_usable(datasette):
    from datasette_google_auth import (  # type: ignore[attr-defined]
        CredentialNotFound,
        get_credential,
    )

    oauth = await add_oauth(datasette)
    await grant(
        datasette,
        RESOURCE_TYPE,
        oauth.id,
        principal=Principal.actor("bob"),
        role="Manager",
        by_actor="alice",
    )
    with pytest.raises(CredentialNotFound):
        await get_credential(datasette, oauth.id, actor=BOB, scopes=[])


# ----------------------------------------------------------- global actions


@pytest.mark.asyncio
async def test_global_actions_denied_by_default(datasette):
    for actor in (None, ALICE):
        assert not await can_connect(datasette, actor)
        assert not await can_add_service_account(datasette, actor)
        assert not await can_admin(datasette, actor)


@pytest.mark.asyncio
async def test_global_actions_honour_permissions_blocks():
    datasette = await make_datasette(
        config={
            "permissions": {
                CONNECT: {"id": ["alice", "bob"]},
                ADD_SERVICE_ACCOUNT: {"id": "alice"},
                ADMIN: {"id": "carol"},
                "permissions-debug": {"id": "*"},
            }
        }
    )
    assert await can_connect(datasette, ALICE)
    assert await can_add_service_account(datasette, ALICE)
    assert not await can_admin(datasette, ALICE)

    assert await can_connect(datasette, BOB)
    assert not await can_add_service_account(datasette, BOB)

    assert not await can_connect(datasette, CAROL)
    assert await can_admin(datasette, CAROL)

    # The same answer over HTTP, for a signed-in actor.
    for actor, allowed in ((ALICE, True), (CAROL, False)):
        response = await datasette.client.get(
            f"/-/check.json?action={ADD_SERVICE_ACCOUNT}",
            cookies={"ds_actor": datasette.client.actor_cookie(actor)},
        )
        assert response.status_code == 200
        assert response.json()["allowed"] is allowed
