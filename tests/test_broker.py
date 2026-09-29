import json

import pytest
from cryptography.fernet import Fernet
from datasette_acl.grants import Principal, grant, revoke
from mock_google import SHEETS_BASE, SHEETS_HOST
from mock_google.keys import SA_TEST
from mock_google.oauth import (
    DEFAULT_USER,
    SCOPE_EMAIL,
    SCOPE_OPENID,
    SCOPE_SHEETS,
    SCOPE_SHEETS_RO,
    GoogleUser,
)

import datasette_google_auth
from datasette_google_auth import (
    Credential,
    CredentialBroken,
    CredentialChanged,
    CredentialForbidden,
    CredentialInfo,
    CredentialNotFound,
    CredentialUndecryptable,
    EncryptionNotConfigured,
    GoogleAuthError,
    GoogleTokenError,
    InvalidServiceAccountKey,
    MissingScopes,
    error_response,
    get_credential,
    list_credentials,
)
from datasette_google_auth.broker import (
    SA_BROKEN_DETAIL,
    TouchThrottle,
    missing_scopes,
)
from datasette_google_auth.crypto import decrypt_credential, encrypt_secret
from datasette_google_auth.internal_db import TABLE, InternalDB
from datasette_google_auth.permissions import (
    ADD_SERVICE_ACCOUNT,
    ADMIN,
    RESOURCE_TYPE,
    seed_manager,
)
from datasette_google_auth.service_account import add_service_account, parse_key
from datasette_google_auth.token_cache import get_token_cache

ALICE = {"id": "alice"}
BOB = {"id": "bob"}
ADMIN_ACTOR = {"id": "admin"}
ROOT = {"id": "root"}
ALL_SCOPES = [SCOPE_OPENID, SCOPE_EMAIL, SCOPE_SHEETS]
SECOND_USER = GoogleUser("100000000000000000002", "second@example.com")
STUDENTS = f"{SHEETS_BASE}/v4/spreadsheets/students"


async def make_datasette(mock_google, **plugin_config):
    datasette = mock_google.datasette(
        plugin_config={"encryption-key": Fernet.generate_key().decode()}
        | plugin_config,
        config={
            "permissions": {
                ADD_SERVICE_ACCOUNT: {"id": "alice"},
                ADMIN: {"id": "admin"},
            }
        },
    )
    await datasette.invoke_startup()
    return datasette


def idb(datasette) -> InternalDB:
    return InternalDB(datasette.get_internal_database())


async def add_oauth(
    datasette, mock_google, owner="alice", user=DEFAULT_USER, scopes=ALL_SCOPES
):
    """An OAuth credential with a live grant at the mock (no consent flow)."""
    refresh_token = mock_google.oauth.issue_refresh_token(user, frozenset(scopes))
    row, _ = await idb(datasette).upsert_oauth(
        owner,
        user.sub,
        google_email=user.email,
        label=user.email,
        scopes=list(scopes),
        secret_encrypted=encrypt_secret(datasette, {"refresh_token": refresh_token}),
        actor_id=owner,
    )
    return row


async def add_sa(datasette, service_account_keys, name="test"):
    """A service account added by alice (so alice is its Manager)."""
    key_json = json.dumps(service_account_keys[name].key_json())
    return await add_service_account(datasette, ALICE, key_json, "")


async def add_unregistered_sa(datasette, service_account_keys):
    """A service account whose key Google no longer accepts (inserted
    directly: add_service_account's live test would refuse it)."""
    key = parse_key(json.dumps(service_account_keys["unregistered"].key_json()))
    row = await idb(datasette).insert(
        type="service_account",
        label="deleted key",
        owner_id="alice",
        created_by="alice",
        secret_encrypted=encrypt_secret(datasette, key.to_secret()),
        google_subject=key.client_id,
        google_email=key.client_email,
    )
    await seed_manager(datasette, row.id, "alice")
    return row


async def share(datasette, credential_id, actor_id="bob", role="User"):
    await grant(
        datasette,
        RESOURCE_TYPE,
        credential_id,
        principal=Principal.actor(actor_id),
        role=role,
        by_actor="alice",
    )


def token_posts(mock_google):
    return mock_google.calls("/token", method="POST")


def sheets_calls(mock_google):
    return mock_google.calls("/v4/spreadsheets/", host=SHEETS_HOST)


# --- Public API ---------------------------------------------------------------


def test_public_api_is_exported():
    for name in datasette_google_auth.__all__:
        assert hasattr(datasette_google_auth, name), name
    assert {
        "list_credentials",
        "get_credential",
        "Credential",
        "CredentialInfo",
        "GoogleAuthError",
        "CredentialNotFound",
        "CredentialForbidden",
        "CredentialBroken",
        "MissingScopes",
        "EncryptionNotConfigured",
        "error_response",
    } <= set(datasette_google_auth.__all__)


@pytest.mark.asyncio
async def test_actor_is_keyword_only(mock_google):
    datasette = await make_datasette(mock_google)
    with pytest.raises(TypeError):
        await list_credentials(datasette, ALICE)  # type: ignore[misc]
    with pytest.raises(TypeError):
        await get_credential(datasette, "x", ALICE, [SCOPE_SHEETS])  # type: ignore[misc]


# --- OAuth: owner only --------------------------------------------------------


@pytest.mark.asyncio
async def test_owner_gets_token_and_makes_requests(mock_google):
    datasette = await make_datasette(mock_google)
    row = await add_oauth(datasette, mock_google)
    cred = await get_credential(datasette, row.id, actor=ALICE, scopes=[SCOPE_SHEETS])
    assert isinstance(cred, Credential)
    assert cred.info == CredentialInfo.from_row(row, ALICE)
    assert cred.info.is_owner

    token = await cred.token()
    assert token.startswith("ya29.mock-")
    assert await cred.token() == token  # cached: one refresh
    assert len(token_posts(mock_google)) == 1

    response = await cred.request("GET", STUDENTS)
    assert response.status_code == 200
    assert response.json()["properties"]["title"] == "Students"
    (call,) = sheets_calls(mock_google)
    assert call.headers["authorization"] == f"Bearer {token}"

    # Nothing secret in what consumers can print.
    refresh_token = (await decrypt_credential(datasette, row))["refresh_token"]
    for text in (repr(cred), cred.info.model_dump_json()):
        assert token not in text
        assert refresh_token not in text


@pytest.mark.asyncio
async def test_request_replaces_caller_authorization_header(mock_google):
    datasette = await make_datasette(mock_google)
    row = await add_oauth(datasette, mock_google)
    cred = await get_credential(datasette, row.id, actor=ALICE, scopes=[SCOPE_SHEETS])
    response = await cred.request(
        "GET",
        STUDENTS,
        headers={"Authorization": "Bearer caller", "X-Extra": "1"},
    )
    assert response.status_code == 200
    (call,) = sheets_calls(mock_google)
    assert call.headers["authorization"] == f"Bearer {await cred.token()}"
    assert call.headers["x-extra"] == "1"


@pytest.mark.asyncio
async def test_other_user_gets_not_found(mock_google):
    datasette = await make_datasette(mock_google)
    row = await add_oauth(datasette, mock_google)
    for actor in (BOB, None, {}, {"name": "no id"}):
        with pytest.raises(CredentialNotFound):
            await get_credential(datasette, row.id, actor=actor, scopes=[])
    with pytest.raises(CredentialNotFound):
        await get_credential(datasette, "no-such-id", actor=ALICE, scopes=[])


@pytest.mark.asyncio
async def test_root_cannot_use_oauth_credential(mock_google):
    datasette = await make_datasette(mock_google)
    row = await add_oauth(datasette, mock_google)
    # An actor called "root" without --root is just another user.
    with pytest.raises(CredentialNotFound):
        await get_credential(datasette, row.id, actor=ROOT, scopes=[])
    # With --root, but google-auth-admin granted only to "admin" in config:
    # root isn't an admin here, so it can't even tell the credential exists.
    datasette.root_enabled = True
    with pytest.raises(CredentialNotFound):
        await get_credential(datasette, row.id, actor=ROOT, scopes=[])
    assert await list_credentials(datasette, actor=ROOT) == []


@pytest.mark.asyncio
async def test_root_as_implicit_admin_gets_forbidden(mock_google):
    # With no google-auth-admin block, --root holds every action, admin
    # included: it can see the credential (admin view) but never use it.
    datasette = mock_google.datasette(
        plugin_config={"encryption-key": Fernet.generate_key().decode()}
    )
    await datasette.invoke_startup()
    datasette.root_enabled = True
    row = await add_oauth(datasette, mock_google)
    with pytest.raises(CredentialForbidden):
        await get_credential(datasette, row.id, actor=ROOT, scopes=[SCOPE_SHEETS])
    assert await list_credentials(datasette, actor=ROOT) == []


@pytest.mark.asyncio
async def test_admin_gets_forbidden(mock_google):
    datasette = await make_datasette(mock_google)
    row = await add_oauth(datasette, mock_google)
    with pytest.raises(CredentialForbidden):
        await get_credential(datasette, row.id, actor=ADMIN_ACTOR, scopes=[])
    # Unknown ids are still not found, admin or not.
    with pytest.raises(CredentialNotFound):
        await get_credential(datasette, "no-such-id", actor=ADMIN_ACTOR, scopes=[])


@pytest.mark.asyncio
async def test_acl_grant_on_oauth_id_is_ignored(mock_google, monkeypatch):
    datasette = await make_datasette(mock_google)
    datasette.root_enabled = True
    row = await add_oauth(datasette, mock_google)
    await grant(
        datasette,
        RESOURCE_TYPE,
        row.id,
        principal=Principal.actor("bob"),
        role="Manager",
        by_actor="root",
    )

    calls = []
    real_allowed = datasette.allowed

    async def spy_allowed(**kwargs):
        calls.append(kwargs)
        return await real_allowed(**kwargs)

    monkeypatch.setattr(datasette, "allowed", spy_allowed)
    with pytest.raises(CredentialNotFound):
        await get_credential(datasette, row.id, actor=BOB, scopes=[])
    assert await list_credentials(datasette, actor=BOB) == []
    cred = await get_credential(datasette, row.id, actor=ALICE, scopes=[SCOPE_SHEETS])
    await cred.token()
    # allowed() was only ever asked global questions (google-auth-admin),
    # never about the OAuth credential.
    assert calls
    assert all(call.get("resource") is None for call in calls)


# --- Service accounts ---------------------------------------------------------


@pytest.mark.asyncio
async def test_user_role_can_use_service_account(mock_google, service_account_keys):
    datasette = await make_datasette(mock_google)
    sa = await add_sa(datasette, service_account_keys)
    await share(datasette, sa.id)

    cred = await get_credential(datasette, sa.id, actor=BOB, scopes=[SCOPE_SHEETS])
    assert not cred.info.is_owner
    response = await cred.request("GET", STUDENTS)
    assert response.status_code == 200
    # The token was minted for exactly the requested scopes.
    assert mock_google.tokens.lookup(await cred.token()).scopes == {SCOPE_SHEETS}
    assert mock_google.tokens.lookup(await cred.token()).name == SA_TEST


@pytest.mark.asyncio
async def test_service_account_without_grant(mock_google, service_account_keys):
    datasette = await make_datasette(mock_google)
    sa = await add_sa(datasette, service_account_keys)
    with pytest.raises(CredentialNotFound):
        await get_credential(datasette, sa.id, actor=BOB, scopes=[SCOPE_SHEETS])
    with pytest.raises(CredentialForbidden):
        await get_credential(datasette, sa.id, actor=ADMIN_ACTOR, scopes=[SCOPE_SHEETS])


@pytest.mark.asyncio
async def test_service_account_needs_scopes(mock_google, service_account_keys):
    datasette = await make_datasette(mock_google)
    sa = await add_sa(datasette, service_account_keys)
    with pytest.raises(ValueError):
        await get_credential(datasette, sa.id, actor=ALICE, scopes=[])


@pytest.mark.asyncio
async def test_service_account_tokens_cached_per_scope_set(
    mock_google, service_account_keys
):
    datasette = await make_datasette(mock_google)
    sa = await add_sa(datasette, service_account_keys)
    before = len(token_posts(mock_google))  # the live test on add
    read = await get_credential(datasette, sa.id, actor=ALICE, scopes=[SCOPE_SHEETS_RO])
    write = await get_credential(datasette, sa.id, actor=ALICE, scopes=[SCOPE_SHEETS])
    assert await read.token() != await write.token()
    assert await read.token() == await read.token()
    assert len(token_posts(mock_google)) == before + 2


@pytest.mark.asyncio
async def test_revoked_grant_takes_effect_on_next_call_with_warm_cache(
    mock_google, service_account_keys
):
    datasette = await make_datasette(mock_google)
    sa = await add_sa(datasette, service_account_keys)
    await share(datasette, sa.id)
    cred = await get_credential(datasette, sa.id, actor=BOB, scopes=[SCOPE_SHEETS])
    await cred.token()
    assert len(get_token_cache(datasette)) == 1  # warm

    await revoke(
        datasette,
        RESOURCE_TYPE,
        sa.id,
        principal=Principal.actor("bob"),
        by_actor="alice",
    )
    # The held Credential re-checks on every call, and so does a new lookup.
    with pytest.raises(CredentialNotFound):
        await cred.token()
    with pytest.raises(CredentialNotFound):
        await cred.request("GET", STUDENTS)
    with pytest.raises(CredentialNotFound):
        await get_credential(datasette, sa.id, actor=BOB, scopes=[SCOPE_SHEETS])
    assert sheets_calls(mock_google) == []
    # alice is unaffected.
    alice_cred = await get_credential(
        datasette, sa.id, actor=ALICE, scopes=[SCOPE_SHEETS]
    )
    assert (await alice_cred.request("GET", STUDENTS)).status_code == 200


@pytest.mark.asyncio
async def test_service_account_invalid_grant_marks_broken(
    mock_google, service_account_keys
):
    datasette = await make_datasette(mock_google)
    row = await add_unregistered_sa(datasette, service_account_keys)
    cred = await get_credential(datasette, row.id, actor=ALICE, scopes=[SCOPE_SHEETS])
    with pytest.raises(CredentialBroken) as excinfo:
        await cred.request("GET", STUDENTS)
    assert excinfo.value.credential_id == row.id
    assert excinfo.value.reconnect_url is None
    broken = await idb(datasette).get(row.id)
    assert broken is not None
    assert broken.status == "broken"
    assert broken.status_detail == SA_BROKEN_DETAIL
    assert "rotate the key" in SA_BROKEN_DETAIL
    assert sheets_calls(mock_google) == []

    # From now on it fails before contacting Google.
    posts = len(token_posts(mock_google))
    with pytest.raises(CredentialBroken) as excinfo:
        await get_credential(datasette, row.id, actor=ALICE, scopes=[SCOPE_SHEETS])
    assert excinfo.value.reconnect_url is None
    assert len(token_posts(mock_google)) == posts


@pytest.mark.asyncio
async def test_service_account_rotated_during_mint_is_not_marked_broken(
    mock_google, service_account_keys, monkeypatch
):
    datasette = await make_datasette(mock_google)
    row = await add_unregistered_sa(datasette, service_account_keys)
    cred = await get_credential(datasette, row.id, actor=ALICE, scopes=[SCOPE_SHEETS])

    from datasette_google_auth import broker

    real_mint = broker.mint_service_account_token

    async def rotate_then_mint(*args, **kwargs):
        good = parse_key(json.dumps(service_account_keys["test"].key_json()))
        await idb(datasette).update_secret(
            row.id, encrypt_secret(datasette, good.to_secret()), actor_id="alice"
        )
        return await real_mint(*args, **kwargs)

    monkeypatch.setattr(broker, "mint_service_account_token", rotate_then_mint)
    with pytest.raises(CredentialChanged):
        await cred.token()
    after = await idb(datasette).get(row.id)
    assert after is not None and after.status == "ok"


# --- Everything else ----------------------------------------------------------


@pytest.mark.asyncio
async def test_delete_in_another_process_fails_next_call(mock_google):
    datasette = await make_datasette(mock_google)
    row = await add_oauth(datasette, mock_google)
    cred = await get_credential(datasette, row.id, actor=ALICE, scopes=[SCOPE_SHEETS])
    await cred.token()
    # Another process: a raw delete, no cache eviction in this one.
    await datasette.get_internal_database().execute_write(
        f"DELETE FROM {TABLE} WHERE id = ?", [row.id]
    )
    assert len(get_token_cache(datasette)) == 1
    with pytest.raises(CredentialNotFound):
        await get_credential(datasette, row.id, actor=ALICE, scopes=[SCOPE_SHEETS])
    with pytest.raises(CredentialNotFound):
        await cred.token()


@pytest.mark.asyncio
async def test_missing_scopes_has_reconnect_url(mock_google):
    datasette = await make_datasette(mock_google)
    row = await add_oauth(
        datasette, mock_google, scopes=[SCOPE_OPENID, SCOPE_EMAIL, SCOPE_SHEETS_RO]
    )
    with pytest.raises(MissingScopes) as excinfo:
        await get_credential(datasette, row.id, actor=ALICE, scopes=[SCOPE_SHEETS])
    assert excinfo.value.missing == [SCOPE_SHEETS]
    # The configured scopes include it, so a plain reconnect asks again.
    assert excinfo.value.reconnect_url == "/-/google-auth/connect"
    assert excinfo.value.not_configured == []
    # Strict matching: spreadsheets doesn't imply spreadsheets.readonly.
    full = await add_oauth(datasette, mock_google, user=SECOND_USER)
    with pytest.raises(MissingScopes):
        await get_credential(datasette, full.id, actor=ALICE, scopes=[SCOPE_SHEETS_RO])


@pytest.mark.asyncio
async def test_missing_scope_that_is_not_configured(mock_google):
    datasette = await make_datasette(mock_google)
    row = await add_oauth(datasette, mock_google)
    drive = "https://www.googleapis.com/auth/drive.file"
    with pytest.raises(MissingScopes) as excinfo:
        await get_credential(
            datasette, row.id, actor=ALICE, scopes=[SCOPE_SHEETS, drive]
        )
    assert excinfo.value.missing == [drive]
    assert excinfo.value.not_configured == [drive]
    assert excinfo.value.reconnect_url is None
    assert "administrator" in str(excinfo.value)


@pytest.mark.asyncio
async def test_no_reconnect_url_without_oauth_config(mock_google):
    datasette = await make_datasette(mock_google, client_id=None, client_secret=None)
    row = await add_oauth(datasette, mock_google, scopes=[SCOPE_OPENID, SCOPE_EMAIL])
    with pytest.raises(MissingScopes) as excinfo:
        await get_credential(datasette, row.id, actor=ALICE, scopes=[SCOPE_SHEETS])
    assert excinfo.value.reconnect_url is None


@pytest.mark.asyncio
async def test_broken_credential_raises(mock_google):
    datasette = await make_datasette(mock_google)
    row = await add_oauth(datasette, mock_google)
    await idb(datasette).mark_broken(row.id, "Google access was revoked")
    with pytest.raises(CredentialBroken) as excinfo:
        await get_credential(datasette, row.id, actor=ALICE, scopes=[SCOPE_SHEETS])
    assert excinfo.value.credential_id == row.id
    assert excinfo.value.detail == "Google access was revoked"
    assert excinfo.value.reconnect_url == "/-/google-auth/connect"
    # Not-found still wins for anyone else.
    with pytest.raises(CredentialNotFound):
        await get_credential(datasette, row.id, actor=BOB, scopes=[SCOPE_SHEETS])


@pytest.mark.asyncio
async def test_revoked_oauth_grant_marks_broken_through_broker(mock_google):
    datasette = await make_datasette(mock_google)
    row = await add_oauth(datasette, mock_google)
    refresh_token = (await decrypt_credential(datasette, row))["refresh_token"]
    async with mock_google.client() as google:
        await google.post("/revoke", data={"token": refresh_token})
    cred = await get_credential(datasette, row.id, actor=ALICE, scopes=[SCOPE_SHEETS])
    with pytest.raises(CredentialBroken) as excinfo:
        await cred.request("GET", STUDENTS)
    assert excinfo.value.reconnect_url == "/-/google-auth/connect"
    assert refresh_token not in str(excinfo.value)
    assert (await idb(datasette).get(row.id)).status == "broken"  # type: ignore[union-attr]


@pytest.mark.asyncio
async def test_401_retries_exactly_once(mock_google):
    datasette = await make_datasette(mock_google)
    row = await add_oauth(datasette, mock_google)
    cred = await get_credential(datasette, row.id, actor=ALICE, scopes=[SCOPE_SHEETS])
    first = await cred.token()
    mock_google.faults.fail("/v4/spreadsheets/", 401, times=1)

    response = await cred.request("GET", STUDENTS)
    assert response.status_code == 200
    calls = sheets_calls(mock_google)
    assert [c.status for c in calls] == [401, 200]
    # The retry used a fresh token, not the evicted one.
    assert calls[0].headers["authorization"] == f"Bearer {first}"
    assert calls[1].headers["authorization"] != f"Bearer {first}"
    assert len(token_posts(mock_google)) == 2


@pytest.mark.asyncio
async def test_401_twice_is_returned_not_retried_again(mock_google):
    datasette = await make_datasette(mock_google)
    row = await add_oauth(datasette, mock_google)
    cred = await get_credential(datasette, row.id, actor=ALICE, scopes=[SCOPE_SHEETS])
    mock_google.faults.fail("/v4/spreadsheets/", 401, times=None)
    response = await cred.request("GET", STUDENTS)
    assert response.status_code == 401
    assert len(sheets_calls(mock_google)) == 2


@pytest.mark.asyncio
async def test_other_errors_are_not_retried(mock_google):
    datasette = await make_datasette(mock_google)
    row = await add_oauth(datasette, mock_google)
    cred = await get_credential(datasette, row.id, actor=ALICE, scopes=[SCOPE_SHEETS])
    response = await cred.request("GET", f"{SHEETS_BASE}/v4/spreadsheets/private")
    assert response.status_code == 403
    assert len(sheets_calls(mock_google)) == 1


@pytest.mark.asyncio
async def test_list_credentials(mock_google, service_account_keys):
    datasette = await make_datasette(mock_google)
    readonly = await add_oauth(
        datasette,
        mock_google,
        scopes=[SCOPE_OPENID, SCOPE_EMAIL, SCOPE_SHEETS_RO],
    )
    full = await add_oauth(datasette, mock_google, user=SECOND_USER)
    bobs = await add_oauth(datasette, mock_google, owner="bob")
    sa = await add_sa(datasette, service_account_keys)
    other_sa = await add_sa(datasette, service_account_keys, name="other")
    await share(datasette, other_sa.id)

    def ids(infos):
        return [info.id for info in infos]

    # Own OAuth first, then usable service accounts; never others' OAuth.
    assert ids(await list_credentials(datasette, actor=ALICE)) == [
        readonly.id,
        full.id,
        sa.id,
        other_sa.id,
    ]
    assert ids(await list_credentials(datasette, actor=BOB)) == [bobs.id, other_sa.id]
    # scopes filter: OAuth needs every scope granted; service accounts pass.
    assert ids(
        await list_credentials(datasette, actor=ALICE, scopes=[SCOPE_SHEETS])
    ) == [
        full.id,
        sa.id,
        other_sa.id,
    ]
    assert ids(
        await list_credentials(
            datasette, actor=ALICE, scopes=[SCOPE_SHEETS_RO, SCOPE_SHEETS]
        )
    ) == [sa.id, other_sa.id]
    # google-auth-admin doesn't widen the list; anonymous gets nothing.
    assert await list_credentials(datasette, actor=ADMIN_ACTOR) == []
    assert await list_credentials(datasette, actor=None) == []
    assert await list_credentials(datasette, actor={}) == []

    infos = {i.id: i for i in await list_credentials(datasette, actor=ALICE)}
    assert infos[full.id].is_owner
    assert infos[full.id].scopes == ALL_SCOPES
    assert infos[sa.id].type == "service_account"
    assert infos[sa.id].scopes == []


@pytest.mark.asyncio
async def test_list_includes_broken_credentials(mock_google):
    datasette = await make_datasette(mock_google)
    row = await add_oauth(datasette, mock_google)
    await idb(datasette).mark_broken(row.id, "revoked")
    (info,) = await list_credentials(datasette, actor=ALICE, scopes=[SCOPE_SHEETS])
    assert (info.status, info.status_detail) == ("broken", "revoked")


@pytest.mark.asyncio
async def test_touch_used_is_throttled(mock_google, monkeypatch):
    datasette = await make_datasette(mock_google)
    row = await add_oauth(datasette, mock_google)
    now = [1000.0]
    datasette._google_auth_touch_throttle = TouchThrottle(clock=lambda: now[0])

    writes = []
    real_touch = InternalDB.touch_used

    async def spy(self, id, actor_id):
        writes.append((id, actor_id))
        return await real_touch(self, id, actor_id)

    monkeypatch.setattr(InternalDB, "touch_used", spy)
    cred = await get_credential(datasette, row.id, actor=ALICE, scopes=[SCOPE_SHEETS])
    for _ in range(3):
        await cred.token()
    await cred.request("GET", STUDENTS)
    assert writes == [(row.id, "alice")]
    touched = await idb(datasette).get(row.id)
    assert touched is not None
    assert touched.last_used_by == "alice"
    assert touched.last_used_at is not None

    now[0] += 59
    await cred.token()
    assert len(writes) == 1
    now[0] += 2
    await cred.token()
    assert len(writes) == 2


def test_missing_scopes_is_strict():
    assert missing_scopes([SCOPE_SHEETS], ALL_SCOPES) == []
    assert missing_scopes([], []) == []
    assert missing_scopes([SCOPE_SHEETS_RO], [SCOPE_SHEETS]) == [SCOPE_SHEETS_RO]


# --- error_response -----------------------------------------------------------


@pytest.mark.parametrize(
    "exc,status,extra",
    [
        (CredentialNotFound("c1"), 404, {}),
        (CredentialForbidden(), 403, {}),
        (
            CredentialBroken("revoked", credential_id="c1", reconnect_url="/connect"),
            409,
            {"reconnect_url": "/connect"},
        ),
        (CredentialBroken("key deleted", credential_id="c1"), 409, {}),
        (
            MissingScopes(["s"], reconnect_url="/connect"),
            403,
            {"reconnect_url": "/connect", "missing": ["s"]},
        ),
        (MissingScopes(["s"], not_configured=["s"]), 403, {"missing": ["s"]}),
        (EncryptionNotConfigured(), 503, {}),
        (CredentialUndecryptable("c1"), 500, {}),
        (CredentialChanged("c1"), 409, {}),
        (GoogleTokenError(500, "backend_error"), 502, {}),
        (InvalidServiceAccountKey("Invalid service account key: bad"), 400, {}),
        (GoogleAuthError("something"), 500, {}),
    ],
)
def test_error_response(exc, status, extra):
    response = error_response(exc)
    assert response.status == status
    assert response.content_type.startswith("application/json")
    assert (
        json.loads(response.body)
        == {
            "ok": False,
            "error": str(exc),
            "code": exc.code,
        }
        | extra
    )


def test_error_response_covers_every_error_class():
    import datasette_google_auth.errors as errors

    classes = [
        obj
        for obj in vars(errors).values()
        if isinstance(obj, type) and issubclass(obj, GoogleAuthError)
    ]
    assert len(classes) >= 10
    for cls in classes:
        assert cls in errors._STATUS, cls.__name__
    assert len({cls.code for cls in classes}) == len(classes)
