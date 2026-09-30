"""The ``google-auth-admin`` "All credentials" view (ticket 15, D6).

The admin may list and delete anyone's credentials, never use them. Page
access, page data, owner display names (``actors_from_ids``), delete
through the shared endpoint, the broker's refusal, and no secrets anywhere.
The API's own filter/field tests are in ``test_api.py``. The Svelte app is
checked by hand; ``test_admin_page_offers_no_use_rename_or_reconnect`` only
guards its source against those controls creeping in.
"""

import json
import re
from pathlib import Path

import pytest
from cryptography.fernet import Fernet
from datasette import hookimpl
from datasette.plugins import pm
from mock_google.oauth import SCOPE_EMAIL, SCOPE_OPENID, SCOPE_SHEETS

from datasette_google_auth import (
    CredentialForbidden,
    get_credential,
    list_credentials,
)
from datasette_google_auth.crypto import encrypt_secret
from datasette_google_auth.internal_db import InternalDB
from datasette_google_auth.page_data import AdminPageData, IndexPageData
from datasette_google_auth.permissions import ADD_SERVICE_ACCOUNT, ADMIN, CONNECT
from datasette_google_auth.service import add_service_account

PAGE = "/-/google-auth/admin"
API = "/-/google-auth/api/admin/credentials"
DEV_PORT = 5187
SHARE_DEV_PORT = 5199
ALL_SCOPES = [SCOPE_OPENID, SCOPE_EMAIL, SCOPE_SHEETS]
ADMIN_PAGE_SOURCE = (
    Path(__file__).parent.parent / "frontend/src/pages/admin/AdminPage.svelte"
)

ALICE = {"id": "alice"}  # connect + add service account
BOB = {"id": "bob"}  # connect only
DAVE = {"id": "dave"}  # no google-auth action at all
ADMIN_ACTOR = {"id": "admin"}

SECRET_WORDS = ('private_key"', "refresh_token", "secret", "BEGIN PRIVATE KEY")


async def make_datasette(mock_google):
    key = Fernet.generate_key().decode()
    datasette = mock_google.datasette(
        plugin_config={"encryption-key": key},
        config={
            "permissions": {
                CONNECT: {"id": ["alice", "bob"]},
                ADD_SERVICE_ACCOUNT: {"id": "alice"},
                ADMIN: {"id": "admin"},
            },
            "plugins": {
                "datasette-vite": {
                    "dev_ports": {
                        "datasette_google_auth": DEV_PORT,
                        "datasette_acl_share": SHARE_DEV_PORT,
                    }
                }
            },
        },
    )
    await datasette.invoke_startup()
    datasette._test_fernet_key = key
    return datasette


def idb(datasette) -> InternalDB:
    return InternalDB(datasette.get_internal_database())


async def add_oauth(datasette, mock_google, owner="alice"):
    refresh_token = mock_google.oauth.issue_refresh_token(scopes=frozenset(ALL_SCOPES))
    row, _ = await idb(datasette).upsert_oauth(
        owner,
        f"sub-{owner}",
        google_email=f"{owner}@example.com",
        label=f"{owner}@example.com",
        scopes=ALL_SCOPES,
        secret_encrypted=encrypt_secret(datasette, {"refresh_token": refresh_token}),
        actor_id=owner,
    )
    return row, refresh_token


async def add_sa(datasette, service_account_keys):
    key = service_account_keys["test"]
    info = await add_service_account(datasette, ALICE, json.dumps(key.key_json()), "")
    return info, key


def page_data_json(html: str) -> dict:
    match = re.search(
        r'<script type="application/json" id="pageData">(.*?)</script>',
        html,
        re.DOTALL,
    )
    assert match, "no #pageData"
    return json.loads(match.group(1))


async def load_page(datasette, actor=ADMIN_ACTOR) -> AdminPageData:
    response = await datasette.client.get(PAGE, actor=actor)
    assert response.status_code == 200
    return AdminPageData.model_validate(page_data_json(response.text))


class ActorDirectory:
    """A stand-in for datasette-accounts: core's ``actors_from_ids`` hook."""

    __name__ = "test-actor-directory"

    def __init__(self, actors=None, error=None):
        self.actors = actors or {}
        self.error = error

    @hookimpl
    def actors_from_ids(self, datasette, actor_ids):
        async def inner():
            if self.error:
                raise self.error
            return {
                actor_id: self.actors.get(actor_id, {"id": actor_id})
                for actor_id in actor_ids
            }

        return inner


@pytest.fixture
def actor_directory():
    plugins = []

    def register(**kwargs):
        plugin = ActorDirectory(**kwargs)
        pm.register(plugin, name=ActorDirectory.__name__)
        plugins.append(plugin)
        return plugin

    yield register
    for plugin in plugins:
        pm.unregister(plugin)


# --- Access -------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("actor", [None, ALICE, BOB, DAVE])
async def test_non_admins_get_403_on_page_and_api(mock_google, actor):
    datasette = await make_datasette(mock_google)
    await add_oauth(datasette, mock_google)
    page = await datasette.client.get(PAGE, actor=actor)
    assert page.status_code == 403
    assert 'id="pageData"' not in page.text
    assert "alice@example.com" not in page.text
    api = await datasette.client.get(API, actor=actor)
    assert api.status_code == 403
    assert api.json()["code"] == "forbidden"
    assert "alice@example.com" not in api.text


# --- Page ---------------------------------------------------------------------


@pytest.mark.asyncio
async def test_admin_page_lists_every_credential(mock_google, service_account_keys):
    datasette = await make_datasette(mock_google)
    alice, _ = await add_oauth(datasette, mock_google)
    bob, _ = await add_oauth(datasette, mock_google, owner="bob")
    sa, _ = await add_sa(datasette, service_account_keys)
    mine, _ = await add_oauth(datasette, mock_google, owner="admin")
    await idb(datasette).mark_broken(bob.id, "revoked")

    response = await datasette.client.get(PAGE, actor=ADMIN_ACTOR)
    assert response.status_code == 200
    assert "<title>All Google credentials" in response.text
    assert f"http://localhost:{DEV_PORT}/src/pages/admin/index.ts" in response.text
    data = AdminPageData.model_validate(page_data_json(response.text))
    assert data.status.is_admin
    assert data.manage_url == "/-/google-auth"
    rows = [(c.id, c.type, c.owner_id, c.status, c.is_owner) for c in data.credentials]
    assert rows == [
        (alice.id, "google_oauth", "alice", "ok", False),
        (bob.id, "google_oauth", "bob", "broken", False),
        (sa.id, "service_account", "alice", "ok", False),
        (mine.id, "google_oauth", "admin", "ok", True),
    ]
    # The page data is the unfiltered API listing.
    api = (await datasette.client.get(API, actor=ADMIN_ACTOR)).json()
    assert page_data_json(response.text)["credentials"] == api["credentials"]


@pytest.mark.asyncio
async def test_admin_page_has_no_share_bundle(mock_google):
    datasette = await make_datasette(mock_google)
    response = await datasette.client.get(PAGE, actor=ADMIN_ACTOR)
    assert f"http://localhost:{SHARE_DEV_PORT}/" not in response.text


@pytest.mark.asyncio
async def test_page_data_offers_nothing_to_use_or_reconnect(mock_google):
    datasette = await make_datasette(mock_google)
    await add_oauth(datasette, mock_google, owner="bob")
    data = page_data_json((await datasette.client.get(PAGE, actor=ADMIN_ACTOR)).text)
    assert set(data) == set(AdminPageData.model_fields)
    # No connect/reconnect URL, no per-row permissions to act on.
    assert "connect_url" not in data
    assert "/-/google-auth/connect" not in json.dumps(data)
    for row in data["credentials"]:
        assert not {"can_edit", "can_manage", "role"} & set(row)


def test_admin_page_offers_no_use_rename_or_reconnect():
    source = ADMIN_PAGE_SOURCE.read_text()
    for forbidden in ("/rename", "rotate-key", "/connect", "RenameDialog"):
        assert forbidden not in source, forbidden
    assert "Reconnect" not in source


@pytest.mark.asyncio
@pytest.mark.parametrize("actor,expected", [(ADMIN_ACTOR, True), (ALICE, False)])
async def test_management_page_links_admins_to_admin_page(mock_google, actor, expected):
    datasette = await make_datasette(mock_google)
    response = await datasette.client.get("/-/google-auth", actor=actor)
    data = IndexPageData.model_validate(page_data_json(response.text))
    assert data.admin_url == (PAGE if expected else None)


# --- Filters (API; the page filters the same list in the browser) -------------


@pytest.mark.asyncio
async def test_filters(mock_google, service_account_keys):
    datasette = await make_datasette(mock_google)
    alice, _ = await add_oauth(datasette, mock_google)
    bob, _ = await add_oauth(datasette, mock_google, owner="bob")
    sa, _ = await add_sa(datasette, service_account_keys)
    await idb(datasette).mark_broken(bob.id, "revoked")

    async def ids(query):
        response = await datasette.client.get(f"{API}?{query}", actor=ADMIN_ACTOR)
        assert response.status_code == 200
        return [c["id"] for c in response.json()["credentials"]]

    assert await ids("owner=alice") == [alice.id, sa.id]
    assert await ids("type=service_account") == [sa.id]
    assert await ids("status=broken") == [bob.id]
    assert await ids("owner=bob&status=ok") == []


# --- Owner display names --------------------------------------------------------


@pytest.mark.asyncio
async def test_names_default_to_ids_without_a_directory(mock_google):
    datasette = await make_datasette(mock_google)
    await add_oauth(datasette, mock_google)
    assert (await load_page(datasette)).actor_names == {}


@pytest.mark.asyncio
async def test_names_come_from_actors_from_ids(mock_google, actor_directory):
    actor_directory(
        actors={
            "alice": {"id": "alice", "display_name": "Alice Anderson"},
            "bob": {"id": "bob", "name": "Bob Brown"},
            "admin": {"id": "admin", "display_name": "admin"},  # same as id
        }
    )
    datasette = await make_datasette(mock_google)
    alice, _ = await add_oauth(datasette, mock_google)
    await add_oauth(datasette, mock_google, owner="bob")
    await add_oauth(datasette, mock_google, owner="carol")  # unknown to the directory
    await idb(datasette).touch_used(alice.id, "admin")

    expected = {"alice": "Alice Anderson", "bob": "Bob Brown"}
    assert (await load_page(datasette)).actor_names == expected
    api = (await datasette.client.get(API, actor=ADMIN_ACTOR)).json()
    assert api["actor_names"] == expected
    # Filtered listings only name the ids they show.
    api = (await datasette.client.get(f"{API}?owner=bob", actor=ADMIN_ACTOR)).json()
    assert api["actor_names"] == {"bob": "Bob Brown"}


@pytest.mark.asyncio
async def test_failing_directory_falls_back_to_ids(mock_google, actor_directory):
    actor_directory(error=RuntimeError("directory is down"))
    datasette = await make_datasette(mock_google)
    await add_oauth(datasette, mock_google)
    data = await load_page(datasette)
    assert data.actor_names == {}
    assert [c.owner_id for c in data.credentials] == ["alice"]


# --- Delete but never use -----------------------------------------------------


@pytest.mark.asyncio
async def test_admin_delete_revokes_at_google(mock_google):
    datasette = await make_datasette(mock_google)
    row, refresh_token = await add_oauth(datasette, mock_google, owner="bob")
    response = await datasette.client.post(
        f"/-/google-auth/api/credentials/{row.id}/delete",
        actor=ADMIN_ACTOR,
        headers={"Sec-Fetch-Site": "same-origin"},
    )
    assert response.status_code == 200
    assert response.json()["revoked"] is True
    assert mock_google.oauth.is_revoked(refresh_token)
    assert len(mock_google.calls("/revoke", method="POST")) == 1
    assert refresh_token not in response.text
    # Gone from the admin's list (what the page refetches after a delete).
    listing = (await datasette.client.get(API, actor=ADMIN_ACTOR)).json()
    assert listing["credentials"] == []


@pytest.mark.asyncio
async def test_admin_can_never_use_others_credentials(
    mock_google, service_account_keys
):
    datasette = await make_datasette(mock_google)
    oauth, _ = await add_oauth(datasette, mock_google)
    sa, _ = await add_sa(datasette, service_account_keys)
    token_calls = len(mock_google.calls("/token"))  # add_sa's live test
    # Seeing them in the admin view grants nothing.
    assert len((await load_page(datasette)).credentials) == 2
    for credential_id in (oauth.id, sa.id):
        with pytest.raises(CredentialForbidden):
            await get_credential(
                datasette,
                credential_id,
                actor=ADMIN_ACTOR,
                scopes=["https://www.googleapis.com/auth/spreadsheets"],
            )
    # The admin listing doesn't widen the consumer listing.
    assert await list_credentials(datasette, actor=ADMIN_ACTOR) == []
    consumer = await datasette.client.get(
        "/-/google-auth/api/credentials", actor=ADMIN_ACTOR
    )
    assert consumer.json()["credentials"] == []
    # And the admin can't rename someone else's credential either (D26).
    rename = await datasette.client.post(
        f"/-/google-auth/api/credentials/{oauth.id}/rename",
        json={"label": "mine now"},
        actor=ADMIN_ACTOR,
        headers={"Sec-Fetch-Site": "same-origin"},
    )
    assert rename.status_code == 403
    assert len(mock_google.calls("/token")) == token_calls


# --- No secrets ---------------------------------------------------------------


@pytest.mark.asyncio
async def test_no_secrets_in_page_or_api(mock_google, service_account_keys):
    datasette = await make_datasette(mock_google)
    alice, alice_token = await add_oauth(datasette, mock_google)
    bob, bob_token = await add_oauth(datasette, mock_google, owner="bob")
    sa, key = await add_sa(datasette, service_account_keys)
    ciphertexts = [
        (await idb(datasette).get(cid)).secret_encrypted.decode()
        for cid in (alice.id, bob.id, sa.id)
    ]
    secrets = [
        alice_token,
        bob_token,
        key.private_key_pem,
        key.private_key_id,
        datasette._test_fernet_key,
        *ciphertexts,
    ]
    page = await datasette.client.get(PAGE, actor=ADMIN_ACTOR)
    api = await datasette.client.get(API, actor=ADMIN_ACTOR)
    for text in (page.text, api.text):
        for word in SECRET_WORDS:
            assert word not in text, word
        for secret in secrets:
            assert secret not in text
