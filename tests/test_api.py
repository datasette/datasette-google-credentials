"""The JSON API (ticket 12) and the admin list endpoint (ticket 15's API)."""

import json
import logging

import pytest
from cryptography.fernet import Fernet
from datasette_acl.grants import Principal, grant
from mock_google.keys import SA_TEST, make_service_account
from mock_google.oauth import SCOPE_EMAIL, SCOPE_OPENID, SCOPE_SHEETS

from datasette_google_auth import (
    CredentialForbidden,
    get_credential,
    list_credentials,
)
from datasette_google_auth.crypto import encrypt_secret
from datasette_google_auth.internal_db import InternalDB
from datasette_google_auth.models import (
    AdminCredentialInfo,
    CredentialInfo,
    DeleteResult,
)
from datasette_google_auth.permissions import (
    ADD_SERVICE_ACCOUNT,
    ADMIN,
    CONNECT,
    RESOURCE_TYPE,
)
from datasette_google_auth.router import MAX_BODY_BYTES, router
from datasette_google_auth.routes import api as api_module
from datasette_google_auth.service import add_service_account

ALICE = {"id": "alice"}
BOB = {"id": "bob"}
CAROL = {"id": "carol"}
ADMIN_ACTOR = {"id": "admin"}
ALL_SCOPES = [SCOPE_OPENID, SCOPE_EMAIL, SCOPE_SHEETS]

API = "/-/google-auth/api"
# Anything that looks like a secret field name must never be in a response.
SECRET_WORDS = ('private_key"', "refresh_token", "secret", "BEGIN PRIVATE KEY")

# What a same-origin browser fetch() sends; datasette.client sends neither
# header, like curl, which Datasette's CSRF check also lets through.
SAME_ORIGIN = {"Sec-Fetch-Site": "same-origin"}


# --- Fixtures and helpers -----------------------------------------------------


async def make_datasette(mock_google, **kwargs):
    plugin_config = {"encryption-key": Fernet.generate_key().decode()}
    plugin_config.update(kwargs.pop("plugin_config", {}))
    datasette = mock_google.datasette(
        plugin_config=plugin_config,
        config={
            "permissions": {
                CONNECT: {"id": ["alice", "bob"]},
                ADD_SERVICE_ACCOUNT: {"id": "alice"},
                ADMIN: {"id": "admin"},
            }
        },
        **kwargs,
    )
    await datasette.invoke_startup()
    return datasette


def idb(datasette) -> InternalDB:
    return InternalDB(datasette.get_internal_database())


async def add_oauth(
    datasette, mock_google, owner="alice", subject="sub-1", scopes=None
):
    """An OAuth credential with a live grant at the mock (no consent flow)."""
    scopes = scopes or ALL_SCOPES
    refresh_token = mock_google.oauth.issue_refresh_token(scopes=frozenset(scopes))
    row, _ = await idb(datasette).upsert_oauth(
        owner,
        subject,
        google_email=f"{owner}-{subject}@example.com",
        label=f"{owner}-{subject}",
        scopes=scopes,
        secret_encrypted=encrypt_secret(datasette, {"refresh_token": refresh_token}),
        actor_id=owner,
    )
    return row, refresh_token


def raw(key) -> str:
    return json.dumps(key.key_json())


async def add_sa(datasette, service_account_keys, name="test"):
    """A service account added by alice (so alice is its Manager)."""
    return await add_service_account(
        datasette, ALICE, raw(service_account_keys[name]), ""
    )


async def share(datasette, credential_id, role, actor_id="bob"):
    await grant(
        datasette,
        RESOURCE_TYPE,
        credential_id,
        principal=Principal.actor(actor_id),
        role=role,
        by_actor="alice",
    )


async def post(datasette, path, body=None, *, actor=None, headers=None, **kwargs):
    return await datasette.client.post(
        API + path,
        json=body,
        actor=actor,
        headers={**SAME_ORIGIN, **(headers or {})},
        **kwargs,
    )


async def get(datasette, path, *, actor=None):
    return await datasette.client.get(API + path, actor=actor)


def assert_no_secrets(text: str, *extra: str) -> None:
    for word in SECRET_WORDS + extra:
        assert word not in text, word


# --- OpenAPI ------------------------------------------------------------------

API_PATHS = {
    ("get", "/-/google-auth/api/status"),
    ("get", "/-/google-auth/api/credentials"),
    ("get", "/-/google-auth/api/admin/credentials"),
    ("post", "/-/google-auth/api/service-accounts"),
    ("post", "/-/google-auth/api/credentials/{credential_id}/rename"),
    ("post", "/-/google-auth/api/credentials/{credential_id}/rotate-key"),
    ("post", "/-/google-auth/api/credentials/{credential_id}/delete"),
}


def test_openapi_documents_every_endpoint():
    doc = router.openapi_document_json()
    operations = {
        (method, path)
        for path, methods in doc["paths"].items()
        for method in methods
        if path.startswith("/-/google-auth/api/")
    }
    assert operations == API_PATHS
    for method, path in API_PATHS:
        operation = doc["paths"][path][method]
        assert "content" in operation["responses"]["200"], (method, path)
    bodies = {
        path: doc["paths"][path]["post"]["requestBody"]["content"]["application/json"][
            "schema"
        ]
        for method, path in API_PATHS
        if method == "post" and not path.endswith("/delete")
    }
    assert len(bodies) == 3
    # key_json is write-only in the schema, so generated types mark it so.
    add = bodies["/-/google-auth/api/service-accounts"]["properties"]["key_json"]
    assert add["writeOnly"] is True
    assert {"AdminCredentialInfo", "CredentialInfo"} <= set(
        doc["components"]["schemas"]
    )


# --- Status -------------------------------------------------------------------


@pytest.mark.asyncio
async def test_status_anonymous_temp_internal_db(mock_google):
    datasette = await make_datasette(mock_google)
    response = await get(datasette, "/status")
    assert response.status_code == 200
    assert response.json() == {
        "encryption_configured": True,
        "oauth_configured": True,
        # No --internal: Datasette uses a throwaway temp file.
        "internal_db_persistent": False,
        "redirect_uri": "http://localhost/-/google-auth/oauth/callback",
        "can_connect": False,
        "can_add_service_account": False,
        "is_admin": False,
    }


@pytest.mark.asyncio
async def test_status_persistent_internal_db(mock_google, tmp_path):
    datasette = await make_datasette(
        mock_google, internal=str(tmp_path / "internal.db")
    )
    response = await get(datasette, "/status")
    assert response.json()["internal_db_persistent"] is True


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "actor,expected",
    [
        (ALICE, (True, True, False)),
        (BOB, (True, False, False)),
        (CAROL, (False, False, False)),
        (ADMIN_ACTOR, (False, False, True)),
    ],
)
async def test_status_permissions(mock_google, actor, expected):
    datasette = await make_datasette(mock_google)
    data = (await get(datasette, "/status", actor=actor)).json()
    assert (
        data["can_connect"],
        data["can_add_service_account"],
        data["is_admin"],
    ) == expected


@pytest.mark.asyncio
async def test_status_unconfigured(mock_google):
    datasette = await make_datasette(
        mock_google,
        plugin_config={
            "encryption-key": None,
            "client_id": None,
            "client_secret": None,
            "redirect_uri": "https://proxy.example/cb",
        },
    )
    data = (await get(datasette, "/status", actor=ALICE)).json()
    assert data["encryption_configured"] is False
    assert data["oauth_configured"] is False
    assert data["redirect_uri"] == "https://proxy.example/cb"


# --- GET /api/credentials -----------------------------------------------------


@pytest.mark.asyncio
async def test_credentials_anonymous_is_empty(mock_google, service_account_keys):
    datasette = await make_datasette(mock_google)
    await add_oauth(datasette, mock_google)
    await add_sa(datasette, service_account_keys)
    response = await get(datasette, "/credentials")
    assert response.status_code == 200
    assert response.json() == {"credentials": []}


@pytest.mark.asyncio
async def test_credentials_lists_own_and_shared(mock_google, service_account_keys):
    datasette = await make_datasette(mock_google)
    alice_oauth, refresh_token = await add_oauth(datasette, mock_google)
    bob_oauth, _ = await add_oauth(datasette, mock_google, owner="bob")
    sa = await add_sa(datasette, service_account_keys)

    alice = (await get(datasette, "/credentials", actor=ALICE)).json()
    assert [c["id"] for c in alice["credentials"]] == [alice_oauth.id, sa.id]
    for credential in alice["credentials"]:
        assert set(credential) == set(CredentialInfo.model_fields)

    bob = (await get(datasette, "/credentials", actor=BOB)).json()
    assert [c["id"] for c in bob["credentials"]] == [bob_oauth.id]

    await share(datasette, sa.id, "User")
    bob = (await get(datasette, "/credentials", actor=BOB)).json()
    assert [(c["id"], c["is_owner"]) for c in bob["credentials"]] == [
        (bob_oauth.id, True),
        (sa.id, False),
    ]
    assert_no_secrets(json.dumps(alice) + json.dumps(bob), refresh_token)


@pytest.mark.asyncio
async def test_credentials_admin_not_widened(mock_google):
    datasette = await make_datasette(mock_google)
    await add_oauth(datasette, mock_google)
    data = (await get(datasette, "/credentials", actor=ADMIN_ACTOR)).json()
    assert data == {"credentials": []}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "query", ["{sheets}", "{openid},{sheets}", "{openid}%20{sheets}", "{sheets},"]
)
async def test_credentials_scopes_filter(mock_google, service_account_keys, query):
    datasette = await make_datasette(mock_google)
    full, _ = await add_oauth(datasette, mock_google)
    await add_oauth(
        datasette, mock_google, subject="sub-2", scopes=[SCOPE_OPENID, SCOPE_EMAIL]
    )
    sa = await add_sa(datasette, service_account_keys)
    scopes = query.format(sheets=SCOPE_SHEETS, openid=SCOPE_OPENID)
    data = (await get(datasette, f"/credentials?scopes={scopes}", actor=ALICE)).json()
    # Service accounts mint any scope, so they always qualify.
    assert [c["id"] for c in data["credentials"]] == [full.id, sa.id]


@pytest.mark.asyncio
async def test_credentials_without_scopes_lists_all(mock_google):
    datasette = await make_datasette(mock_google)
    await add_oauth(datasette, mock_google)
    await add_oauth(
        datasette, mock_google, subject="sub-2", scopes=[SCOPE_OPENID, SCOPE_EMAIL]
    )
    for query in ("", "?scopes=", "?scopes=,"):
        data = (await get(datasette, "/credentials" + query, actor=ALICE)).json()
        assert len(data["credentials"]) == 2, query


# --- POST /api/service-accounts -----------------------------------------------


@pytest.mark.asyncio
async def test_add_service_account(mock_google, service_account_keys):
    datasette = await make_datasette(mock_google)
    key = service_account_keys["test"]
    response = await post(
        datasette,
        "/service-accounts",
        {"label": "  Reports  ", "key_json": raw(key)},
        actor=ALICE,
    )
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["label"] == "Reports"
    assert data["type"] == "service_account"
    assert data["google_email"] == data["share_with_email"] == SA_TEST
    assert data["is_owner"] is True
    assert set(data) == set(CredentialInfo.model_fields) | {"share_with_email"}
    assert_no_secrets(response.text, key.private_key_pem, key.private_key_id)
    assert [row.id for row in await idb(datasette).list_all()] == [data["id"]]


@pytest.mark.asyncio
async def test_add_service_account_label_defaults_to_email(
    mock_google, service_account_keys
):
    datasette = await make_datasette(mock_google)
    response = await post(
        datasette,
        "/service-accounts",
        {"key_json": raw(service_account_keys["test"])},
        actor=ALICE,
    )
    assert response.json()["label"] == SA_TEST


@pytest.mark.asyncio
@pytest.mark.parametrize("actor", [None, BOB, ADMIN_ACTOR])
async def test_add_service_account_forbidden(mock_google, service_account_keys, actor):
    datasette = await make_datasette(mock_google)
    response = await post(
        datasette,
        "/service-accounts",
        {"key_json": raw(service_account_keys["test"])},
        actor=actor,
    )
    assert response.status_code == 403
    assert response.json()["code"] == "forbidden"
    assert await idb(datasette).list_all() == []


@pytest.mark.asyncio
async def test_add_service_account_without_encryption_key(
    mock_google, service_account_keys
):
    datasette = await make_datasette(
        mock_google, plugin_config={"encryption-key": None}
    )
    response = await post(
        datasette,
        "/service-accounts",
        {"key_json": raw(service_account_keys["test"])},
        actor=ALICE,
    )
    assert response.status_code == 503
    assert response.json()["code"] == "encryption_not_configured"


@pytest.mark.asyncio
async def test_add_service_account_label_too_long(mock_google, service_account_keys):
    datasette = await make_datasette(mock_google)
    response = await post(
        datasette,
        "/service-accounts",
        {"label": "x" * 201, "key_json": raw(service_account_keys["test"])},
        actor=ALICE,
    )
    assert response.status_code == 400
    assert response.json()["code"] == "invalid_label"


@pytest.mark.asyncio
async def test_add_service_account_body_validation(mock_google):
    datasette = await make_datasette(mock_google)
    for body in (
        {},
        {"key_json": {"type": "service_account"}},
        {"key_json": "", "x": 1},
    ):
        response = await post(datasette, "/service-accounts", body, actor=ALICE)
        assert response.status_code == 400, body


MARKER = "SEKRITMARKER"


def malformed_keys(service_account_keys) -> list[str]:
    """Bad key files, each carrying MARKER where a secret would be."""
    key = service_account_keys["test"]
    pem = key.private_key_pem
    return [
        f"not json {MARKER}",
        f'{{"type": "service_account", "private_key": "{MARKER}',
        json.dumps(key.key_json(private_key=f"-----BEGIN PRIVATE KEY-----\n{MARKER}")),
        json.dumps(key.key_json(private_key=pem.replace("\n", "\n" + MARKER, 3))),
        # (A short identifier-like `type` IS echoed, by design: ticket 07.)
        json.dumps(key.key_json(type=f"{MARKER}!")),
        json.dumps(key.key_json(type=f"service account {MARKER} " + pem)),
        json.dumps(key.key_json(client_email=f"{MARKER}@evil.example")),
        json.dumps(key.key_json(private_key_id="")),
        json.dumps(key.key_json(private_key="\ud800" + MARKER)),
        json.dumps([MARKER]),
    ]


@pytest.mark.asyncio
async def test_malformed_key_never_echoed(mock_google, service_account_keys, caplog):
    datasette = await make_datasette(mock_google)
    caplog.set_level(logging.DEBUG)
    for key_json in malformed_keys(service_account_keys):
        response = await post(
            datasette, "/service-accounts", {"key_json": key_json}, actor=ALICE
        )
        assert response.status_code == 400, key_json
        assert response.json()["code"] == "invalid_service_account_key"
        assert MARKER not in response.text
        assert "PRIVATE KEY" not in response.text
    assert MARKER not in caplog.text
    assert "PRIVATE KEY" not in caplog.text
    assert await idb(datasette).list_all() == []


@pytest.mark.asyncio
async def test_key_rejected_by_google_not_echoed(
    mock_google, service_account_keys, caplog
):
    datasette = await make_datasette(mock_google)
    caplog.set_level(logging.DEBUG)
    key = service_account_keys["unregistered"]
    response = await post(
        datasette, "/service-accounts", {"key_json": raw(key)}, actor=ALICE
    )
    assert response.status_code == 400
    assert response.json()["code"] == "invalid_service_account_key"
    for text in (response.text, caplog.text):
        assert_no_secrets(text, key.private_key_pem, key.private_key_id)


@pytest.mark.asyncio
async def test_unexpected_error_is_sanitized(
    mock_google, service_account_keys, caplog, monkeypatch
):
    datasette = await make_datasette(mock_google)
    caplog.set_level(logging.DEBUG)

    async def explode(datasette, actor, raw_key, label):
        raise RuntimeError(f"boom {raw_key}")

    monkeypatch.setattr(api_module, "add_service_account", explode)
    key = service_account_keys["test"]
    response = await post(
        datasette, "/service-accounts", {"key_json": raw(key)}, actor=ALICE
    )
    assert response.status_code == 500
    assert response.json()["code"] == "internal_error"
    assert "RuntimeError" in caplog.text
    # The stack trace shows code lines (including the raise above), never the
    # message, which here quotes the whole key file.
    assert_no_secrets(response.text, key.private_key_pem, key.private_key_id)
    for material in (key.private_key_pem, key.private_key_id, "BEGIN PRIVATE KEY"):
        assert material not in caplog.text


@pytest.mark.asyncio
async def test_body_over_limit_rejected(mock_google, service_account_keys):
    datasette = await make_datasette(mock_google)
    key_json = raw(service_account_keys["test"])
    padded = key_json[:-1] + ', "padding": "' + "x" * MAX_BODY_BYTES + '"}'
    response = await post(
        datasette, "/service-accounts", {"key_json": padded}, actor=ALICE
    )
    assert response.status_code == 413
    assert response.json()["code"] == "payload_too_large"
    assert "BEGIN" not in response.text
    assert await idb(datasette).list_all() == []
    # Nothing reached Google: the body was refused before parsing.
    assert not mock_google.calls("/token")


@pytest.mark.asyncio
async def test_body_over_limit_without_content_length(mock_google):
    datasette = await make_datasette(mock_google)

    async def chunks():
        for _ in range(MAX_BODY_BYTES // 1024 + 2):
            yield b"x" * 1024

    response = await datasette.client.post(
        API + "/service-accounts",
        content=chunks(),
        actor=ALICE,
        headers={**SAME_ORIGIN, "content-type": "application/json"},
    )
    assert response.status_code == 413


@pytest.mark.asyncio
async def test_body_just_under_limit_accepted(mock_google, service_account_keys):
    datasette = await make_datasette(mock_google)
    key_json = raw(service_account_keys["test"])
    body = json.dumps({"label": "", "key_json": key_json})
    label = "x" * (MAX_BODY_BYTES - len(body) - 20)
    response = await post(
        datasette,
        "/service-accounts",
        {"label": label, "key_json": key_json},
        actor=ALICE,
    )
    # Through the size check to the label check.
    assert response.status_code == 400
    assert response.json()["code"] == "invalid_label"


# --- CSRF ---------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "headers",
    [
        {"Sec-Fetch-Site": "cross-site"},
        {"Sec-Fetch-Site": "same-site"},
        {"Sec-Fetch-Site": None, "Origin": "https://evil.example"},
    ],
)
async def test_csrf_blocks_cross_origin_posts(mock_google, headers):
    datasette = await make_datasette(mock_google)
    row, _ = await add_oauth(datasette, mock_google)
    send = {k: v for k, v in headers.items() if v is not None}
    for path, body in (
        (f"/credentials/{row.id}/rename", {"label": "pwned"}),
        (f"/credentials/{row.id}/delete", None),
        ("/service-accounts", {"key_json": "{}"}),
    ):
        response = await datasette.client.post(
            API + path, json=body, actor=ALICE, headers=send
        )
        assert response.status_code == 403, path
    after = await idb(datasette).get(row.id)
    assert after is not None and after.label == row.label


@pytest.mark.asyncio
async def test_csrf_allows_same_origin(mock_google):
    datasette = await make_datasette(mock_google)
    row, _ = await add_oauth(datasette, mock_google)
    response = await datasette.client.post(
        API + f"/credentials/{row.id}/rename",
        json={"label": "Mine"},
        actor=ALICE,
        headers={"Origin": "http://localhost"},
    )
    assert response.status_code == 200
    assert response.json()["label"] == "Mine"


# --- Rename -------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "actor,status",
    [(ALICE, 200), (BOB, 404), (None, 404), (ADMIN_ACTOR, 403)],
)
async def test_rename_oauth(mock_google, actor, status):
    datasette = await make_datasette(mock_google)
    row, _ = await add_oauth(datasette, mock_google)
    response = await post(
        datasette, f"/credentials/{row.id}/rename", {"label": " New "}, actor=actor
    )
    assert response.status_code == status
    after = await idb(datasette).get(row.id)
    assert after is not None
    if status == 200:
        assert response.json()["label"] == after.label == "New"
        assert set(response.json()) == set(CredentialInfo.model_fields)
    else:
        assert after.label == row.label


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "role,status",
    [(None, 404), ("User", 403), ("Editor", 200), ("Manager", 200)],
)
async def test_rename_service_account(mock_google, service_account_keys, role, status):
    datasette = await make_datasette(mock_google)
    sa = await add_sa(datasette, service_account_keys)
    if role:
        await share(datasette, sa.id, role)
    response = await post(
        datasette, f"/credentials/{sa.id}/rename", {"label": "Shared"}, actor=BOB
    )
    assert response.status_code == status


@pytest.mark.asyncio
async def test_rename_unknown_and_invalid(mock_google):
    datasette = await make_datasette(mock_google)
    row, _ = await add_oauth(datasette, mock_google)
    response = await post(
        datasette, "/credentials/nope/rename", {"label": "x"}, actor=ALICE
    )
    assert response.status_code == 404
    assert response.json()["code"] == "not_found"
    response = await post(
        datasette, f"/credentials/{row.id}/rename", {"label": "  "}, actor=ALICE
    )
    assert response.status_code == 400
    assert response.json()["code"] == "invalid_label"


# --- Rotate key ---------------------------------------------------------------


def new_test_key(mock_google):
    key = make_service_account(SA_TEST)
    mock_google.tokens.register_service_account(SA_TEST, key.public_key)
    return key


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "role,status",
    [(None, 404), ("User", 403), ("Editor", 200), ("Manager", 200)],
)
async def test_rotate_key_permissions(mock_google, service_account_keys, role, status):
    datasette = await make_datasette(mock_google)
    sa = await add_sa(datasette, service_account_keys)
    if role:
        await share(datasette, sa.id, role)
    key = new_test_key(mock_google)
    response = await post(
        datasette, f"/credentials/{sa.id}/rotate-key", {"key_json": raw(key)}, actor=BOB
    )
    assert response.status_code == status
    if status == 200:
        assert response.json()["id"] == sa.id
        assert_no_secrets(response.text, key.private_key_pem, key.private_key_id)


@pytest.mark.asyncio
async def test_rotate_key_admin_forbidden_and_oauth_not_found(
    mock_google, service_account_keys
):
    datasette = await make_datasette(mock_google)
    sa = await add_sa(datasette, service_account_keys)
    row, _ = await add_oauth(datasette, mock_google)
    key = raw(new_test_key(mock_google))
    response = await post(
        datasette,
        f"/credentials/{sa.id}/rotate-key",
        {"key_json": key},
        actor=ADMIN_ACTOR,
    )
    assert response.status_code == 403
    response = await post(
        datasette, f"/credentials/{row.id}/rotate-key", {"key_json": key}, actor=ALICE
    )
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_rotate_key_malformed_or_different_account(
    mock_google, service_account_keys, caplog
):
    datasette = await make_datasette(mock_google)
    caplog.set_level(logging.DEBUG)
    sa = await add_sa(datasette, service_account_keys)
    other = service_account_keys["other"]
    for key_json in [*malformed_keys(service_account_keys), raw(other)]:
        response = await post(
            datasette,
            f"/credentials/{sa.id}/rotate-key",
            {"key_json": key_json},
            actor=ALICE,
        )
        assert response.status_code == 400, key_json
        assert response.json()["code"] == "invalid_service_account_key"
        assert MARKER not in response.text
        assert_no_secrets(response.text, other.private_key_pem, other.private_key_id)
    assert MARKER not in caplog.text
    assert "PRIVATE KEY" not in caplog.text


# --- Delete -------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "actor,status",
    [(BOB, 404), (None, 404), (ALICE, 200), (ADMIN_ACTOR, 200)],
)
async def test_delete_oauth(mock_google, actor, status):
    datasette = await make_datasette(mock_google)
    row, refresh_token = await add_oauth(datasette, mock_google)
    response = await post(datasette, f"/credentials/{row.id}/delete", actor=actor)
    assert response.status_code == status
    revokes = mock_google.calls("/revoke", method="POST")
    if status == 200:
        data = response.json()
        assert (
            data
            == DeleteResult(id=row.id, type="google_oauth", revoked=True).model_dump()
        )
        assert len(revokes) == 1
        assert await idb(datasette).get(row.id) is None
        assert refresh_token not in response.text
    else:
        assert not revokes
        assert await idb(datasette).get(row.id) is not None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "actor,role,status",
    [
        (BOB, None, 404),
        (BOB, "User", 403),
        (BOB, "Editor", 403),
        (BOB, "Manager", 200),
        (ALICE, None, 200),
        (ADMIN_ACTOR, None, 200),
    ],
)
async def test_delete_service_account(
    mock_google, service_account_keys, actor, role, status
):
    datasette = await make_datasette(mock_google)
    sa = await add_sa(datasette, service_account_keys)
    if role:
        await share(datasette, sa.id, role)
    response = await post(datasette, f"/credentials/{sa.id}/delete", actor=actor)
    assert response.status_code == status
    if status == 200:
        key = service_account_keys["test"]
        data = response.json()
        assert data["client_email"] == SA_TEST
        # The key id is what the user deletes in Cloud console; not a secret.
        assert data["private_key_id"] == key.private_key_id
        assert key.private_key_pem not in response.text


@pytest.mark.asyncio
async def test_delete_unknown(mock_google):
    datasette = await make_datasette(mock_google)
    response = await post(datasette, "/credentials/nope/delete", actor=ADMIN_ACTOR)
    assert response.status_code == 404


# --- Admin list (ticket 15's API) ---------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("actor", [None, ALICE, BOB])
async def test_admin_list_forbidden(mock_google, actor):
    datasette = await make_datasette(mock_google)
    await add_oauth(datasette, mock_google)
    response = await get(datasette, "/admin/credentials", actor=actor)
    assert response.status_code == 403
    assert response.json()["code"] == "forbidden"


@pytest.mark.asyncio
async def test_admin_list_sees_everything(mock_google, service_account_keys):
    datasette = await make_datasette(mock_google)
    alice, alice_token = await add_oauth(datasette, mock_google)
    bob, bob_token = await add_oauth(datasette, mock_google, owner="bob")
    sa = await add_sa(datasette, service_account_keys)
    response = await get(datasette, "/admin/credentials", actor=ADMIN_ACTOR)
    assert response.status_code == 200
    credentials = response.json()["credentials"]
    assert [(c["id"], c["owner_id"], c["is_owner"]) for c in credentials] == [
        (alice.id, "alice", False),
        (bob.id, "bob", False),
        (sa.id, "alice", False),
    ]
    for credential in credentials:
        assert set(credential) == set(AdminCredentialInfo.model_fields)
    key = service_account_keys["test"]
    assert_no_secrets(
        response.text, alice_token, bob_token, key.private_key_pem, key.private_key_id
    )


@pytest.mark.asyncio
async def test_admin_list_filters(mock_google, service_account_keys):
    datasette = await make_datasette(mock_google)
    alice, _ = await add_oauth(datasette, mock_google)
    bob, _ = await add_oauth(datasette, mock_google, owner="bob")
    sa = await add_sa(datasette, service_account_keys)
    await idb(datasette).mark_broken(bob.id, "revoked")

    async def ids(query):
        response = await get(
            datasette, "/admin/credentials?" + query, actor=ADMIN_ACTOR
        )
        return [c["id"] for c in response.json()["credentials"]]

    assert await ids("owner=alice") == [alice.id, sa.id]
    assert await ids("type=google_oauth") == [alice.id, bob.id]
    assert await ids("type=service_account") == [sa.id]
    assert await ids("status=broken") == [bob.id]
    assert await ids("owner=alice&type=google_oauth&status=ok") == [alice.id]
    assert await ids("owner=nobody") == []
    assert await ids("owner=&type=") == [alice.id, bob.id, sa.id]


@pytest.mark.asyncio
async def test_admin_can_list_and_delete_but_never_use(mock_google):
    datasette = await make_datasette(mock_google)
    row, _ = await add_oauth(datasette, mock_google)
    listed = (await get(datasette, "/admin/credentials", actor=ADMIN_ACTOR)).json()
    assert [c["id"] for c in listed["credentials"]] == [row.id]
    # Listing grants nothing: the broker still refuses the admin.
    with pytest.raises(CredentialForbidden):
        await get_credential(datasette, row.id, actor=ADMIN_ACTOR, scopes=[])
    assert await list_credentials(datasette, actor=ADMIN_ACTOR) == []
    assert not mock_google.calls("/token")
    # ...but may delete it, which revokes at Google.
    response = await post(datasette, f"/credentials/{row.id}/delete", actor=ADMIN_ACTOR)
    assert response.status_code == 200
    assert response.json()["revoked"] is True
    assert len(mock_google.calls("/revoke", method="POST")) == 1


# --- No GoogleAuthError escapes to Datasette ----------------------------------


def assert_json_error(response, status, code):
    assert response.status_code == status, response.text
    assert response.headers["content-type"].startswith("application/json")
    body = response.json()
    assert body["ok"] is False and body["code"] == code


@pytest.mark.asyncio
async def test_error_path_per_post_endpoint(mock_google, service_account_keys):
    datasette = await make_datasette(mock_google)
    sa = await add_sa(datasette, service_account_keys)
    other = raw(service_account_keys["other"])
    cases = [
        ("/service-accounts", {"key_json": "{"}, 400, "invalid_service_account_key"),
        (f"/credentials/{sa.id}/rename", {"label": ""}, 400, "invalid_label"),
        (
            f"/credentials/{sa.id}/rotate-key",
            {"key_json": other},
            400,
            "invalid_service_account_key",
        ),
        ("/credentials/nope/delete", None, 404, "not_found"),
    ]
    for path, body, status, code in cases:
        response = await post(datasette, path, body, actor=ALICE)
        assert_json_error(response, status, code)


LEAKY = "sa-leak@project.iam.gserviceaccount.com"


class LeakyError(Exception):
    pass


def _raiser(exc):
    async def fn(*args, **kwargs):
        raise exc

    return fn


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "target,method,path,body",
    [
        ("get_status", "get", "/status", None),
        ("list_credentials", "get", "/credentials", None),
        ("list_all_credentials", "get", "/admin/credentials", None),
        ("add_service_account", "post", "/service-accounts", {"key_json": "{}"}),
        ("rename", "post", "/credentials/x/rename", {"label": "y"}),
        (
            "rotate_service_account_key",
            "post",
            "/credentials/x/rotate-key",
            {"key_json": "{}"},
        ),
        ("delete", "post", "/credentials/x/delete", None),
    ],
)
async def test_every_handler_returns_json_for_google_auth_errors(
    mock_google, monkeypatch, target, method, path, body
):
    from datasette_google_auth.errors import GoogleAuthError

    datasette = await make_datasette(mock_google)
    # A base GoogleAuthError (500 in error_response) whose message names an
    # SA email: it must come back as JSON, not escape to Datasette.
    monkeypatch.setattr(api_module, target, _raiser(GoogleAuthError(f"bad {LEAKY}")))
    if method == "get":
        response = await get(datasette, path, actor=ALICE)
    else:
        response = await post(datasette, path, body, actor=ALICE)
    assert_json_error(response, 500, "google_auth_error")
