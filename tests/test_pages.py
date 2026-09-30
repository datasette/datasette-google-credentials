"""The ``/-/google-auth`` management page (ticket 14), server side.

Page data, setup-notice flags, the menu link, the share dialog's assets and
the list endpoint's page fields. The Svelte app itself is checked by hand
(ticket 19's checklist). datasette-vite runs in dev mode (``dev_ports``) for
both this plugin and datasette-acl-share, so nothing needs a build.
"""

import json
import re

import pytest
from cryptography.fernet import Fernet
from datasette_acl.grants import Principal, grant
from mock_google.oauth import (
    OAUTH_CLIENT_SECRET,
    SCOPE_EMAIL,
    SCOPE_OPENID,
    SCOPE_SHEETS,
)

from datasette_google_auth import sharing
from datasette_google_auth.crypto import encrypt_secret
from datasette_google_auth.internal_db import InternalDB
from datasette_google_auth.page_data import IndexPageData
from datasette_google_auth.permissions import (
    ADD_SERVICE_ACCOUNT,
    ADMIN,
    CONNECT,
    RESOURCE_TYPE,
)
from datasette_google_auth.service import add_service_account

DEV_PORT = 5187
SHARE_DEV_PORT = 5199
SHARE_JS = f"http://localhost:{SHARE_DEV_PORT}/src/main.ts"
PAGE = "/-/google-auth"
MENU_LINK = f'<a href="{PAGE}">Google accounts</a>'
ALL_SCOPES = [SCOPE_OPENID, SCOPE_EMAIL, SCOPE_SHEETS]

ALICE = {"id": "alice"}  # connect + add service account
BOB = {"id": "bob"}  # connect only
CAROL = {"id": "carol"}  # add service account only
DAVE = {"id": "dave"}  # no google-auth action at all
ADMIN_ACTOR = {"id": "admin"}


async def make_datasette(mock_google, *, plugin_config=None, permissions=None, **kw):
    config = {"encryption-key": Fernet.generate_key().decode()}
    config.update(plugin_config or {})
    datasette = mock_google.datasette(
        plugin_config=config,
        config={
            "permissions": permissions
            or {
                CONNECT: {"id": ["alice", "bob"]},
                ADD_SERVICE_ACCOUNT: {"id": ["alice", "carol"]},
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
        **kw,
    )
    await datasette.invoke_startup()
    return datasette


async def get(datasette, path, actor=None):
    return await datasette.client.get(path, actor=actor)


def page_data(html: str) -> IndexPageData:
    match = re.search(
        r'<script type="application/json" id="pageData">(.*?)</script>',
        html,
        re.DOTALL,
    )
    assert match, "no #pageData"
    return IndexPageData.model_validate(json.loads(match.group(1)))


async def load_page(datasette, actor) -> IndexPageData:
    response = await get(datasette, PAGE, actor)
    assert response.status_code == 200
    return page_data(response.text)


async def add_oauth(datasette, mock_google, owner="alice", scopes=None):
    scopes = scopes or ALL_SCOPES
    refresh_token = mock_google.oauth.issue_refresh_token(scopes=frozenset(scopes))
    row, _ = await InternalDB(datasette.get_internal_database()).upsert_oauth(
        owner,
        f"sub-{owner}-{len(scopes)}",
        google_email=f"{owner}@example.com",
        label=f"{owner}@example.com",
        scopes=scopes,
        secret_encrypted=encrypt_secret(datasette, {"refresh_token": refresh_token}),
        actor_id=owner,
    )
    return row, refresh_token


async def add_sa(datasette, service_account_keys, name="test"):
    key = service_account_keys[name]
    info = await add_service_account(datasette, ALICE, json.dumps(key.key_json()), "")
    return info, key


async def share(datasette, credential_id, role, actor_id="bob"):
    await grant(
        datasette,
        RESOURCE_TYPE,
        credential_id,
        principal=Principal.actor(actor_id),
        role=role,
        by_actor="alice",
    )


# --- Access -------------------------------------------------------------------


@pytest.mark.asyncio
async def test_anonymous_gets_403_even_when_actions_are_open_to_all(mock_google):
    datasette = await make_datasette(
        mock_google,
        permissions={CONNECT: True, ADD_SERVICE_ACCOUNT: True},
    )
    response = await get(datasette, PAGE)
    assert response.status_code == 403
    assert 'id="pageData"' not in response.text
    assert SHARE_JS not in response.text


@pytest.mark.asyncio
async def test_signed_in_without_actions_sees_shared_service_accounts(
    mock_google, service_account_keys
):
    # No google-auth action, but a service account shared with them: the
    # page is where they find its email to share sheets with.
    datasette = await make_datasette(mock_google)
    data = await load_page(datasette, DAVE)
    assert data.credentials == []
    assert not (
        data.status.can_connect
        or data.status.can_add_service_account
        or data.status.is_admin
    )

    info, _ = await add_sa(datasette, service_account_keys)
    await share(datasette, info.id, "User", actor_id="dave")
    data = await load_page(datasette, DAVE)
    assert [(c.id, c.role, c.can_edit, c.can_manage) for c in data.credentials] == [
        (info.id, "User", False, False)
    ]
    assert data.credentials[0].google_email == info.google_email


@pytest.mark.asyncio
async def test_page_data_lists_own_oauth_and_usable_service_accounts(
    mock_google, service_account_keys
):
    datasette = await make_datasette(mock_google)
    alice_oauth, _ = await add_oauth(datasette, mock_google)
    await add_oauth(datasette, mock_google, owner="bob")
    info, _ = await add_sa(datasette, service_account_keys)

    data = await load_page(datasette, ALICE)
    assert [(c.id, c.type) for c in data.credentials] == [
        (alice_oauth.id, "google_oauth"),
        (info.id, "service_account"),
    ]
    assert data.actor_id == "alice"
    assert data.connect_url == "/-/google-auth/connect?return_to=%2F-%2Fgoogle-auth"

    # The admin sees no one else's credentials here (that's ticket 15's view).
    assert (await load_page(datasette, ADMIN_ACTOR)).credentials == []


@pytest.mark.asyncio
async def test_page_data_contains_no_secrets(mock_google, service_account_keys):
    encryption_key = Fernet.generate_key().decode()
    datasette = await make_datasette(
        mock_google, plugin_config={"encryption-key": encryption_key}
    )
    _, refresh_token = await add_oauth(datasette, mock_google)
    _, key = await add_sa(datasette, service_account_keys)
    # Make sure the list has actually been used, so last_used_* is populated.
    idb = InternalDB(datasette.get_internal_database())
    for row in await idb.list_all():
        await idb.touch_used(row.id, "alice")

    response = await get(datasette, PAGE, ALICE)
    assert response.status_code == 200
    html = response.text
    for secret in (
        refresh_token,
        key.private_key_id,
        "PRIVATE KEY",
        "private_key",
        "refresh_token",
        "secret_encrypted",
        "client_secret",
        OAUTH_CLIENT_SECRET,
        encryption_key,
        "last_used_by",
    ):
        assert secret not in html, secret
    raw = json.loads(
        re.search(r'id="pageData">(.*?)</script>', html, re.DOTALL).group(1)
    )
    assert set(raw) == set(IndexPageData.model_fields)
    for credential in raw["credentials"]:
        assert credential["last_used_at"]


# --- Setup notices ------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "plugin_config,encryption,oauth",
    [
        ({}, True, True),
        ({"encryption-key": None}, False, True),
        ({"client_id": None}, True, False),
        ({"client_secret": None}, True, False),
        ({"encryption-key": None, "client_id": None}, False, False),
    ],
)
async def test_setup_notice_flags(mock_google, plugin_config, encryption, oauth):
    datasette = await make_datasette(mock_google, plugin_config=plugin_config)
    for actor in (ALICE, ADMIN_ACTOR):
        status = (await load_page(datasette, actor)).status
        assert status.encryption_configured is encryption
        assert status.oauth_configured is oauth
        # The exact URI admins paste into Google Cloud console.
        assert status.redirect_uri == "http://localhost/-/google-auth/oauth/callback"
        # Full setup steps are for those who can fix it.
        assert status.is_admin is (actor is ADMIN_ACTOR)


@pytest.mark.asyncio
async def test_redirect_uri_override_is_shown(mock_google):
    uri = "https://datasette.example.com/-/google-auth/oauth/callback"
    datasette = await make_datasette(mock_google, plugin_config={"redirect_uri": uri})
    assert (await load_page(datasette, ADMIN_ACTOR)).status.redirect_uri == uri


@pytest.mark.asyncio
async def test_root_counts_as_admin_for_setup_steps(mock_google):
    # `--root` holds every action unless config restricts google-auth-admin
    # to others (D25); then root sees the "ask an admin" notices.
    datasette = await make_datasette(mock_google, permissions={CONNECT: {"id": "x"}})
    datasette.root_enabled = True
    assert (await load_page(datasette, {"id": "root"})).status.is_admin is True


@pytest.mark.asyncio
async def test_in_memory_warning_flag(mock_google, tmp_path):
    # No --internal: a temp file deleted at exit (D30).
    datasette = await make_datasette(mock_google)
    status = (await load_page(datasette, ALICE)).status
    assert status.internal_db_persistent is False

    datasette = await make_datasette(
        mock_google, internal=str(tmp_path / "internal.db")
    )
    status = (await load_page(datasette, ALICE)).status
    assert status.internal_db_persistent is True


# --- Menu link ----------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "actor,expected",
    [
        (ALICE, True),
        (BOB, True),
        (CAROL, True),
        (ADMIN_ACTOR, True),
        (DAVE, False),
        (None, False),
    ],
)
async def test_menu_link_only_for_permitted_actors(mock_google, actor, expected):
    datasette = await make_datasette(mock_google)
    response = await get(datasette, "/", actor)
    assert response.status_code == 200
    assert (MENU_LINK in response.text) is expected


@pytest.mark.asyncio
async def test_menu_link_never_for_anonymous(mock_google):
    # Open to everyone in config, but the page 403s anonymous actors.
    datasette = await make_datasette(
        mock_google, permissions={CONNECT: True, ADD_SERVICE_ACCOUNT: True}
    )
    assert MENU_LINK not in (await get(datasette, "/")).text
    assert MENU_LINK in (await get(datasette, "/", DAVE)).text


# --- Share dialog assets ------------------------------------------------------


@pytest.mark.asyncio
async def test_share_assets_only_on_the_management_page(mock_google):
    datasette = await make_datasette(mock_google)
    response = await get(datasette, PAGE, ALICE)
    assert f'<script type="module" src="{SHARE_JS}"></script>' in response.text
    data = page_data(response.text)
    assert data.share is not None
    assert data.share.features == sharing.share_features()

    for path in ("/", "/-/versions", "/-/google-auth/oauth/callback"):
        assert SHARE_JS not in (await get(datasette, path, ALICE)).text, path


def test_is_management_page():
    class Request:
        def __init__(self, path):
            self.path = path

    assert sharing.is_management_page(sharing.TEMPLATE, Request(PAGE))
    # Same template, another page (ticket 15's admin view).
    assert not sharing.is_management_page(sharing.TEMPLATE, Request(PAGE + "/admin"))
    # Same path, another template (the 403 page).
    assert not sharing.is_management_page("error.html", Request(PAGE))
    assert not sharing.is_management_page(sharing.TEMPLATE, None)


@pytest.mark.asyncio
async def test_page_degrades_without_share_bundle(mock_google, monkeypatch):
    # datasette-acl-share's built assets are gitignored: without its
    # manifest, datasette-vite raises ValueError. No Share buttons, no crash.
    def unbuilt(datasette):
        raise ValueError("Entrypoint src/main.ts not found in manifest")

    monkeypatch.setattr(sharing, "datasette_share_assets", unbuilt)
    datasette = await make_datasette(mock_google)
    response = await get(datasette, PAGE, ALICE)
    assert response.status_code == 200
    assert page_data(response.text).share is None
    assert f"localhost:{SHARE_DEV_PORT}" not in response.text


# --- GET /api/credentials page fields ------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "role,can_edit,can_manage",
    [("User", False, False), ("Editor", True, False), ("Manager", True, True)],
)
async def test_list_reports_role_and_allowed_changes(
    mock_google, service_account_keys, role, can_edit, can_manage
):
    datasette = await make_datasette(mock_google)
    info, _ = await add_sa(datasette, service_account_keys)
    await share(datasette, info.id, role)

    listed = (await get(datasette, "/-/google-auth/api/credentials", BOB)).json()[
        "credentials"
    ]
    assert [(c["role"], c["can_edit"], c["can_manage"]) for c in listed] == [
        (role, can_edit, can_manage)
    ]
    # The creator is Manager.
    alice = (await get(datasette, "/-/google-auth/api/credentials", ALICE)).json()
    assert alice["credentials"][0]["role"] == "Manager"


@pytest.mark.asyncio
async def test_list_reports_last_used_and_missing_scopes(mock_google):
    datasette = await make_datasette(mock_google)
    full, _ = await add_oauth(datasette, mock_google)
    limited, _ = await add_oauth(
        datasette, mock_google, scopes=[SCOPE_OPENID, SCOPE_EMAIL]
    )
    await InternalDB(datasette.get_internal_database()).touch_used(full.id, "alice")

    listed = {
        c["id"]: c
        for c in (await get(datasette, "/-/google-auth/api/credentials", ALICE)).json()[
            "credentials"
        ]
    }
    assert listed[full.id]["missing_scopes"] == []
    assert listed[full.id]["last_used_at"]
    assert listed[full.id]["role"] is None
    assert listed[full.id]["can_edit"] and listed[full.id]["can_manage"]
    # "Limited access": the default config asks for spreadsheets.
    assert listed[limited.id]["missing_scopes"] == [SCOPE_SHEETS]
    assert listed[limited.id]["last_used_at"] is None
