import json

import jwt
import pytest
from cryptography.fernet import Fernet
from datasette_acl.grants import Principal, grant
from fixtures_google import GOOGLE_BASE_URLS
from mock_google import MOCK_HOST
from mock_google.keys import SA_TEST, make_service_account

from datasette_google_auth.crypto import decrypt_credential
from datasette_google_auth.errors import (
    CredentialForbidden,
    CredentialNotFound,
    EncryptionNotConfigured,
    GoogleAuthError,
    GoogleTokenError,
    InvalidServiceAccountKey,
)
from datasette_google_auth.internal_db import InternalDB
from datasette_google_auth.permissions import (
    ADD_SERVICE_ACCOUNT,
    ADMIN,
    RESOURCE_TYPE,
    can_manage_sa,
)
from datasette_google_auth.service_account import (
    SECRET_FIELDS,
    ServiceAccountKey,
    add_service_account,
    mint_service_account_token,
    parse_key,
    rotate_service_account_key,
)
from datasette_google_auth.token_cache import CacheKey, get_token_cache
from datasette_google_auth.tokens import Token

ALICE = {"id": "alice"}
BOB = {"id": "bob"}
ADMIN_ACTOR = {"id": "admin"}
TOKEN_URL = GOOGLE_BASE_URLS["oauth_token"]
EVIL_TOKEN_URI = "https://evil.example/token"


async def make_datasette(mock_google, *, encryption=True, permissions=None):
    plugin_config = (
        {"encryption-key": Fernet.generate_key().decode()} if encryption else {}
    )
    datasette = mock_google.datasette(
        plugin_config=plugin_config,
        config={
            "permissions": permissions
            or {ADD_SERVICE_ACCOUNT: {"id": "alice"}, ADMIN: {"id": "admin"}}
        },
    )
    await datasette.invoke_startup()
    return datasette


def raw(key, **overrides) -> str:
    return json.dumps(key.key_json(**overrides))


def idb(datasette) -> InternalDB:
    return InternalDB(datasette.get_internal_database())


def token_posts(mock_google):
    return mock_google.calls("/token", method="POST")


# --- parse_key --------------------------------------------------------------


def test_parse_key_keeps_only_needed_fields(service_account_keys):
    sa = service_account_keys["test"]
    key = parse_key(raw(sa, token_uri=EVIL_TOKEN_URI).encode())
    assert key == ServiceAccountKey(
        client_email=sa.client_email,
        private_key=sa.private_key_pem,
        private_key_id=sa.private_key_id,
        project_id=sa.project_id,
        client_id=sa.client_id,
    )
    assert set(key.to_secret()) == set(SECRET_FIELDS)
    assert "PRIVATE KEY" not in repr(key)


@pytest.mark.parametrize(
    "overrides,message",
    [
        ({"type": "authorized_user"}, "type is 'authorized_user'"),
        ({"type": None}, "type is missing"),
        ({"private_key": "-----BEGIN PRIVATE KEY-----\nnope\n"}, "not a PEM-encoded"),
        ({"client_email": "someone@example.com"}, "gserviceaccount.com"),
        ({"private_key_id": ""}, "'private_key_id' is missing"),
        ({"project_id": None}, "'project_id' is missing"),
        ({"client_email": 7}, "'client_email' is missing"),
    ],
)
def test_parse_key_rejects(service_account_keys, overrides, message):
    with pytest.raises(InvalidServiceAccountKey) as info:
        parse_key(raw(service_account_keys["test"], **overrides))
    assert message in str(info.value)


def test_parse_key_rejects_non_rsa_key(service_account_keys):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    pem = (
        ec.generate_private_key(ec.SECP256R1())
        .private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        .decode()
    )
    with pytest.raises(InvalidServiceAccountKey, match="not an RSA key"):
        parse_key(raw(service_account_keys["test"], private_key=pem))


@pytest.mark.parametrize("value", ["not json {", "[1, 2]", b"\xff\xfe"])
def test_parse_key_rejects_non_objects(value):
    with pytest.raises(InvalidServiceAccountKey):
        parse_key(value)


# --- mint -------------------------------------------------------------------


@pytest.mark.asyncio
async def test_mint_token(mock_google, service_account_keys):
    datasette = await make_datasette(mock_google)
    key = parse_key(raw(service_account_keys["test"]))
    token = await mint_service_account_token(
        datasette, key, ["https://www.googleapis.com/auth/spreadsheets.readonly"]
    )
    assert isinstance(token, Token)
    assert token.access_token.startswith("ya29.mock-")
    assert token.scopes == {"https://www.googleapis.com/auth/spreadsheets.readonly"}

    [call] = token_posts(mock_google)
    assert call.form["grant_type"] == "urn:ietf:params:oauth:grant-type:jwt-bearer"
    assertion = call.form["assertion"]
    header = jwt.get_unverified_header(assertion)
    claims = jwt.decode(
        assertion,
        service_account_keys["test"].public_key,
        algorithms=["RS256"],
        audience=TOKEN_URL,
    )
    assert header["kid"] == key.private_key_id
    assert claims["iss"] == claims["sub"] == key.client_email
    assert claims["exp"] - claims["iat"] == 3600


@pytest.mark.asyncio
async def test_mint_token_maps_other_errors(mock_google, service_account_keys):
    datasette = await make_datasette(mock_google)
    mock_google.faults.fail("/token", 503)
    key = parse_key(raw(service_account_keys["test"]))
    with pytest.raises(GoogleTokenError) as info:
        await mint_service_account_token(datasette, key, ["scope-a"])
    assert info.value.status == 503
    assert info.value.error == "internal_failure"
    assert info.value.description == "mock_google: injected fault"


# --- add_service_account ----------------------------------------------------


@pytest.mark.asyncio
async def test_add_service_account(mock_google, service_account_keys):
    datasette = await make_datasette(mock_google)
    sa = service_account_keys["test"]
    info = await add_service_account(datasette, ALICE, raw(sa), "  Team SA  ")

    assert info.model_dump() == {
        "id": info.id,
        "type": "service_account",
        "label": "Team SA",
        "google_email": SA_TEST,
        "scopes": [],
        "status": "ok",
        "status_detail": None,
        "is_owner": True,
    }
    row = await idb(datasette).get(info.id)
    assert row is not None
    assert (row.owner_id, row.created_by) == ("alice", "alice")
    assert row.google_subject == sa.client_id
    # The live test exchange happened before the insert.
    assert len(token_posts(mock_google)) == 1
    # The creator is seeded Manager.
    assert await can_manage_sa(datasette, ALICE, row)


@pytest.mark.asyncio
async def test_label_defaults_to_client_email(mock_google, service_account_keys):
    datasette = await make_datasette(mock_google)
    info = await add_service_account(
        datasette, ALICE, raw(service_account_keys["test"]), " "
    )
    assert info.label == SA_TEST


@pytest.mark.asyncio
async def test_stored_blob_has_only_kept_fields_encrypted(
    mock_google, service_account_keys
):
    datasette = await make_datasette(mock_google)
    sa = service_account_keys["test"]
    info = await add_service_account(datasette, ALICE, raw(sa), "SA")
    row = await idb(datasette).get(info.id)
    assert row is not None
    assert b"PRIVATE KEY" not in row.secret_encrypted
    assert sa.private_key_id.encode() not in row.secret_encrypted
    secret = await decrypt_credential(datasette, row)
    assert secret == {
        "client_email": sa.client_email,
        "private_key": sa.private_key_pem,
        "private_key_id": sa.private_key_id,
        "project_id": sa.project_id,
    }


@pytest.mark.asyncio
async def test_token_uri_is_ignored(mock_google, service_account_keys):
    datasette = await make_datasette(mock_google)
    await add_service_account(
        datasette,
        ALICE,
        raw(service_account_keys["test"], token_uri=EVIL_TOKEN_URI),
        "SA",
    )
    # Exactly one request, to the configured token URL, and nothing else.
    assert [(r.method, r.host, r.path) for r in mock_google.requests] == [
        ("POST", MOCK_HOST, "/token")
    ]
    claims = jwt.decode(
        mock_google.requests[0].form["assertion"], options={"verify_signature": False}
    )
    assert claims["aud"] == TOKEN_URL


@pytest.mark.asyncio
async def test_invalid_grant_on_test_exchange_saves_nothing(
    mock_google, service_account_keys
):
    datasette = await make_datasette(mock_google)
    with pytest.raises(InvalidServiceAccountKey, match="Google rejected this key"):
        await add_service_account(
            datasette, ALICE, raw(service_account_keys["unregistered"]), "SA"
        )
    assert len(token_posts(mock_google)) == 1
    assert await idb(datasette).list_all() == []


@pytest.mark.asyncio
async def test_google_outage_on_test_exchange_saves_nothing(
    mock_google, service_account_keys
):
    datasette = await make_datasette(mock_google)
    with pytest.raises(GoogleTokenError) as info:
        await add_service_account(
            datasette, ALICE, raw(service_account_keys["token_500"]), "SA"
        )
    assert info.value.status == 500
    assert await idb(datasette).list_all() == []


@pytest.mark.asyncio
async def test_add_requires_permission(mock_google, service_account_keys):
    datasette = await make_datasette(mock_google)
    for actor in (BOB, None):
        with pytest.raises(CredentialForbidden):
            await add_service_account(
                datasette, actor, raw(service_account_keys["test"]), "SA"
            )
    assert mock_google.requests == []
    assert await idb(datasette).list_all() == []


@pytest.mark.asyncio
async def test_add_requires_encryption(mock_google, service_account_keys):
    datasette = await make_datasette(mock_google, encryption=False)
    with pytest.raises(EncryptionNotConfigured):
        await add_service_account(
            datasette, ALICE, raw(service_account_keys["test"]), "SA"
        )
    assert mock_google.requests == []


# --- rotate_service_account_key ---------------------------------------------


@pytest.mark.asyncio
async def test_rotate_key(mock_google, service_account_keys):
    datasette = await make_datasette(mock_google)
    info = await add_service_account(
        datasette, ALICE, raw(service_account_keys["test"]), "SA"
    )
    before = await idb(datasette).get(info.id)
    assert before is not None

    # Warm the cache with a token for the old key.
    cache = get_token_cache(datasette)
    await cache.get_or_fetch(CacheKey.for_row(before, ["s"]), lambda: _fake_token())
    assert len(cache) == 1

    # A new key for the same account; Google now only accepts the new one.
    new_sa = make_service_account(SA_TEST)
    mock_google.tokens.register_service_account(SA_TEST, new_sa.public_key)
    rotated = await rotate_service_account_key(datasette, ALICE, info.id, raw(new_sa))

    assert rotated.id == info.id
    after = await idb(datasette).get(info.id)
    assert after is not None
    assert after.updated_by == "alice"
    assert after.updated_at is not None
    secret = await decrypt_credential(datasette, after)
    assert secret["private_key_id"] == new_sa.private_key_id
    assert len(cache) == 0


async def _fake_token() -> Token:
    return Token.from_expires_in("cached", 3600, ["s"])


@pytest.mark.asyncio
async def test_rotate_with_different_email_is_rejected(
    mock_google, service_account_keys
):
    datasette = await make_datasette(mock_google)
    info = await add_service_account(
        datasette, ALICE, raw(service_account_keys["test"]), "SA"
    )
    calls_before = len(mock_google.requests)
    with pytest.raises(InvalidServiceAccountKey, match="different service account"):
        await rotate_service_account_key(
            datasette, ALICE, info.id, raw(service_account_keys["other"])
        )
    # Rejected before any exchange; the stored key is unchanged.
    assert len(mock_google.requests) == calls_before
    row = await idb(datasette).get(info.id)
    assert row is not None
    secret = await decrypt_credential(datasette, row)
    assert secret["private_key_id"] == service_account_keys["test"].private_key_id


@pytest.mark.asyncio
async def test_rotate_with_rejected_key_keeps_old_key(
    mock_google, service_account_keys
):
    datasette = await make_datasette(mock_google)
    info = await add_service_account(
        datasette, ALICE, raw(service_account_keys["test"]), "SA"
    )
    unknown = make_service_account(SA_TEST)  # never registered with the mock
    with pytest.raises(InvalidServiceAccountKey, match="Google rejected this key"):
        await rotate_service_account_key(datasette, ALICE, info.id, raw(unknown))
    row = await idb(datasette).get(info.id)
    assert row is not None
    assert row.updated_at is None


@pytest.mark.asyncio
async def test_rotate_permissions(mock_google, service_account_keys):
    datasette = await make_datasette(mock_google)
    info = await add_service_account(
        datasette, ALICE, raw(service_account_keys["test"]), "SA"
    )
    key = raw(service_account_keys["test"])

    # No access at all: indistinguishable from a missing id.
    with pytest.raises(CredentialNotFound):
        await rotate_service_account_key(datasette, BOB, info.id, key)
    with pytest.raises(CredentialNotFound):
        await rotate_service_account_key(datasette, None, info.id, key)
    with pytest.raises(CredentialNotFound):
        await rotate_service_account_key(datasette, ALICE, "no-such-id", key)
    # Can see it (User role, or google-auth-admin) but not edit it.
    with pytest.raises(CredentialForbidden):
        await rotate_service_account_key(datasette, ADMIN_ACTOR, info.id, key)
    await grant(
        datasette,
        RESOURCE_TYPE,
        info.id,
        principal=Principal.actor("bob"),
        role="User",
        by_actor="alice",
    )
    with pytest.raises(CredentialForbidden):
        await rotate_service_account_key(datasette, BOB, info.id, key)
    # Editor may rotate.
    await grant(
        datasette,
        RESOURCE_TYPE,
        info.id,
        principal=Principal.actor("bob"),
        role="Editor",
        by_actor="alice",
    )
    rotated = await rotate_service_account_key(datasette, BOB, info.id, key)
    assert rotated.is_owner is False


@pytest.mark.asyncio
async def test_rotate_rejects_oauth_credentials(mock_google, service_account_keys):
    datasette = await make_datasette(mock_google)
    row, _ = await idb(datasette).upsert_oauth(
        "alice",
        "sub-1",
        google_email="alice@example.com",
        label="alice@example.com",
        scopes=["openid"],
        secret_encrypted=b"x",
        actor_id="alice",
    )
    with pytest.raises(CredentialNotFound):
        await rotate_service_account_key(
            datasette, ALICE, row.id, raw(service_account_keys["test"])
        )


# --- no key material in errors ----------------------------------------------


def _bad_inputs(sa):
    pem = sa.private_key_pem
    return {
        "wrong type": raw(sa, type="authorized_user"),
        "pem in type": raw(sa, type=pem),
        "pem in email": raw(sa, client_email=pem),
        "truncated pem": raw(sa, private_key=pem[:200]),
        "missing key id": raw(sa, private_key_id=None),
        "not json": raw(sa)[:-5],
    }


@pytest.mark.parametrize(
    "case",
    [
        "wrong type",
        "pem in type",
        "pem in email",
        "truncated pem",
        "missing key id",
        "not json",
        "unregistered",
        "rotate different email",
    ],
)
@pytest.mark.asyncio
async def test_errors_never_contain_key_material(
    mock_google, service_account_keys, case
):
    datasette = await make_datasette(mock_google)
    sa = service_account_keys["test"]
    secrets = [sa.private_key_pem, sa.private_key_id]
    if case == "unregistered":
        sa = service_account_keys["unregistered"]
        secrets = [sa.private_key_pem, sa.private_key_id]
        call = add_service_account(datasette, ALICE, raw(sa), "SA")
    elif case == "rotate different email":
        info = await add_service_account(datasette, ALICE, raw(sa), "SA")
        other = service_account_keys["other"]
        secrets += [other.private_key_pem, other.private_key_id]
        call = rotate_service_account_key(datasette, ALICE, info.id, raw(other))
    else:
        call = add_service_account(datasette, ALICE, _bad_inputs(sa)[case], "SA")

    with pytest.raises(GoogleAuthError) as info:
        await call
    error = info.value
    text = " ".join(
        [str(error), repr(error), str(error.__cause__), str(error.__context__)]
    )
    for secret in secrets:
        assert secret not in text
    # No fragment of the PEM body either.
    for line in secrets[0].splitlines()[1:-1]:
        assert line not in text
