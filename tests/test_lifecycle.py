import dataclasses
import json
from urllib.parse import parse_qs, urlencode, urlsplit

import pytest
from cryptography.fernet import Fernet
from datasette import hookimpl
from datasette.plugins import pm
from datasette_acl.grants import Principal, grant, list_grants
from mock_google.keys import PROJECT_ID, SA_TEST, make_service_account
from mock_google.oauth import (
    DEFAULT_REDIRECT_URI,
    SCOPE_EMAIL,
    SCOPE_OPENID,
    SCOPE_SHEETS,
)

from datasette_google_credentials import (
    CredentialBroken,
    CredentialChanged,
    CredentialForbidden,
    CredentialNotFound,
    get_credential,
)
from datasette_google_credentials import service as service_module
from datasette_google_credentials.broker import SA_BROKEN_DETAIL
from datasette_google_credentials.crypto import decrypt_credential, encrypt_secret
from datasette_google_credentials.errors import InvalidLabel
from datasette_google_credentials.events import EVENTS, mark_broken
from datasette_google_credentials.internal_db import InternalDB
from datasette_google_credentials.oauth import BROKEN_DETAIL, FLOW_COOKIE
from datasette_google_credentials.permissions import (
    ADD_SERVICE_ACCOUNT,
    ADMIN,
    CONNECT,
    RESOURCE_TYPE,
    seed_manager,
)
from datasette_google_credentials.service import (
    DeleteResult,
    add_service_account,
    cloud_console_url,
    delete,
    reconnect_url,
    rename,
    rotate_service_account_key,
)
from datasette_google_credentials.service_account import parse_key
from datasette_google_credentials.token_cache import get_token_cache

ALICE = {"id": "alice"}
BOB = {"id": "bob"}
ADMIN_ACTOR = {"id": "admin"}
ALL_SCOPES = [SCOPE_OPENID, SCOPE_EMAIL, SCOPE_SHEETS]

EVENT_NAMES = {
    "google-credential-created",
    "google-credential-reconnected",
    "google-credential-rotated",
    "google-credential-deleted",
    "google-credential-broken",
}


# --- Fixtures and helpers -----------------------------------------------------


class EventRecorder:
    def __init__(self):
        self.events = []

    @hookimpl
    def track_event(self, datasette, event):
        if event.name.startswith("google-credential-"):
            self.events.append(event)

    def names(self):
        return [event.name for event in self.events]

    def dumps(self) -> str:
        """Everything an event consumer could see, as one string."""
        return "\n".join(
            repr(event)
            + json.dumps(dataclasses.asdict(event), default=str)
            + json.dumps(event.properties(), default=str)
            for event in self.events
        )


@pytest.fixture
def events():
    recorder = EventRecorder()
    pm.register(recorder, name="test-lifecycle-events")
    try:
        yield recorder
    finally:
        pm.unregister(name="test-lifecycle-events")


async def make_datasette(mock_google, **plugin_config):
    datasette = mock_google.datasette(
        plugin_config={"encryption-key": Fernet.generate_key().decode()}
        | plugin_config,
        config={
            "permissions": {
                CONNECT: {"id": ["alice", "bob"]},
                ADD_SERVICE_ACCOUNT: {"id": "alice"},
                ADMIN: {"id": "admin"},
            }
        },
    )
    await datasette.invoke_startup()
    return datasette


def idb(datasette) -> InternalDB:
    return InternalDB(datasette.get_internal_database())


async def add_oauth(datasette, mock_google, owner="alice"):
    """An OAuth credential with a live grant at the mock (no consent flow)."""
    refresh_token = mock_google.oauth.issue_refresh_token(scopes=frozenset(ALL_SCOPES))
    row, _ = await idb(datasette).upsert_oauth(
        owner,
        "sub-1",
        google_email="user@example.com",
        label="user@example.com",
        scopes=ALL_SCOPES,
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


async def connect(datasette, mock_google, actor=ALICE):
    """The full Connect Google flow against the mock."""
    response = await datasette.client.get(
        "/-/google-credentials/connect?" + urlencode({"return_to": "/"}), actor=actor
    )
    assert response.status_code == 302
    cookie = response.cookies[FLOW_COOKIE]
    async with mock_google.client() as google:
        consent = await google.get(response.headers["location"])
    location = consent.headers["location"]
    assert location.startswith(DEFAULT_REDIRECT_URI)
    parts = urlsplit(location)
    response = await datasette.client.get(
        parts.path + "?" + parts.query, actor=actor, cookies={FLOW_COOKIE: cookie}
    )
    assert response.status_code == 302
    return response


def revoke_calls(mock_google):
    return mock_google.calls("/revoke", method="POST")


async def cached_count(datasette, credential_id) -> int:
    cache = get_token_cache(datasette)
    return sum(1 for key in cache._entries if key.credential_id == credential_id)


# --- Registration -------------------------------------------------------------


@pytest.mark.asyncio
async def test_five_events_registered(mock_google):
    datasette = await make_datasette(mock_google)
    names = {cls.name for cls in datasette.event_classes}
    assert EVENT_NAMES <= names
    assert {cls.name for cls in EVENTS} == EVENT_NAMES


def test_service_module_reexports_rotate():
    from datasette_google_credentials import service_account

    assert (
        service_module.rotate_service_account_key
        is service_account.rotate_service_account_key
    )


# --- Rename -------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "actor,expected",
    [
        (ALICE, None),
        (BOB, CredentialNotFound),
        (ADMIN_ACTOR, CredentialForbidden),
        (None, CredentialNotFound),
    ],
)
async def test_rename_oauth_permissions(mock_google, actor, expected):
    datasette = await make_datasette(mock_google)
    row, _ = await add_oauth(datasette, mock_google)
    if expected is None:
        info = await rename(datasette, actor, row.id, "  Work account  ")
        assert info.label == "Work account"
        after = await idb(datasette).get(row.id)
        assert after is not None
        assert (after.label, after.updated_by) == ("Work account", "alice")
    else:
        with pytest.raises(expected):
            await rename(datasette, actor, row.id, "New")
        assert (await idb(datasette).get(row.id)).label == row.label  # type: ignore[union-attr]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "role,actor,expected",
    [
        (None, ALICE, None),  # creator = Manager
        ("Manager", BOB, None),
        ("Editor", BOB, None),
        ("User", BOB, CredentialForbidden),
        (None, BOB, CredentialNotFound),
        (None, ADMIN_ACTOR, CredentialForbidden),
        (None, None, CredentialNotFound),
    ],
)
async def test_rename_service_account_permissions(
    mock_google, service_account_keys, role, actor, expected
):
    datasette = await make_datasette(mock_google)
    info = await add_sa(datasette, service_account_keys)
    if role:
        await share(datasette, info.id, role)
    if expected is None:
        renamed = await rename(datasette, actor, info.id, "Reporting")
        assert renamed.label == "Reporting"
    else:
        with pytest.raises(expected):
            await rename(datasette, actor, info.id, "Reporting")
        assert (await idb(datasette).get(info.id)).label == info.label  # type: ignore[union-attr]


@pytest.mark.asyncio
@pytest.mark.parametrize("label", ["", "   ", "x" * 201])
async def test_rename_rejects_bad_labels(mock_google, label):
    datasette = await make_datasette(mock_google)
    row, _ = await add_oauth(datasette, mock_google)
    with pytest.raises(InvalidLabel):
        await rename(datasette, ALICE, row.id, label)


@pytest.mark.asyncio
async def test_rename_unknown_id(mock_google):
    datasette = await make_datasette(mock_google)
    with pytest.raises(CredentialNotFound):
        await rename(datasette, ALICE, "nope", "x")


# --- Reconnect ----------------------------------------------------------------


@pytest.mark.asyncio
async def test_reconnect_url(mock_google, service_account_keys):
    datasette = await make_datasette(mock_google)
    row, _ = await add_oauth(datasette, mock_google)
    url = await reconnect_url(datasette, ALICE, row.id)
    parts = urlsplit(url)
    assert parts.path == "/-/google-credentials/connect"
    assert parse_qs(parts.query) == {"return_to": ["/-/google-credentials"]}

    with pytest.raises(CredentialNotFound):
        await reconnect_url(datasette, BOB, row.id)
    with pytest.raises(CredentialForbidden):
        await reconnect_url(datasette, ADMIN_ACTOR, row.id)
    sa = await add_sa(datasette, service_account_keys)
    with pytest.raises(CredentialNotFound):
        await reconnect_url(datasette, ALICE, sa.id)


# --- Delete: permissions --------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "actor,expected",
    [
        (ALICE, None),
        (ADMIN_ACTOR, None),
        (BOB, CredentialNotFound),
        (None, CredentialNotFound),
    ],
)
async def test_delete_oauth_permissions(mock_google, actor, expected):
    datasette = await make_datasette(mock_google)
    row, _ = await add_oauth(datasette, mock_google)
    if expected is None:
        result = await delete(datasette, actor, row.id)
        assert result.revoked is True
        assert await idb(datasette).get(row.id) is None
    else:
        with pytest.raises(expected):
            await delete(datasette, actor, row.id)
        assert await idb(datasette).get(row.id) is not None
        assert not revoke_calls(mock_google)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "role,actor,expected",
    [
        (None, ALICE, None),  # creator = Manager
        ("Manager", BOB, None),
        (None, ADMIN_ACTOR, None),
        ("Editor", BOB, CredentialForbidden),
        ("User", BOB, CredentialForbidden),
        (None, BOB, CredentialNotFound),
        (None, None, CredentialNotFound),
    ],
)
async def test_delete_service_account_permissions(
    mock_google, service_account_keys, role, actor, expected
):
    datasette = await make_datasette(mock_google)
    info = await add_sa(datasette, service_account_keys)
    if role:
        await share(datasette, info.id, role)
    if expected is None:
        await delete(datasette, actor, info.id)
        assert await idb(datasette).get(info.id) is None
    else:
        with pytest.raises(expected):
            await delete(datasette, actor, info.id)
        assert await idb(datasette).get(info.id) is not None


@pytest.mark.asyncio
async def test_delete_unknown_or_already_deleted(mock_google):
    datasette = await make_datasette(mock_google)
    with pytest.raises(CredentialNotFound):
        await delete(datasette, ALICE, "nope")
    row, _ = await add_oauth(datasette, mock_google)
    await delete(datasette, ALICE, row.id)
    with pytest.raises(CredentialNotFound):
        await delete(datasette, ALICE, row.id)


# --- Delete: OAuth revoke -------------------------------------------------------


@pytest.mark.asyncio
async def test_oauth_delete_revokes_refresh_token(mock_google):
    datasette = await make_datasette(mock_google)
    row, refresh_token = await add_oauth(datasette, mock_google)
    cred = await get_credential(datasette, row.id, actor=ALICE, scopes=[SCOPE_SHEETS])
    await cred.token()
    assert await cached_count(datasette, row.id) == 1

    result = await delete(datasette, ALICE, row.id)

    assert result == DeleteResult(
        id=row.id, type="google_oauth", revoked=True, revoke_error=None
    )
    (call,) = revoke_calls(mock_google)
    assert call.form == {"token": refresh_token}
    assert mock_google.oauth.is_revoked(refresh_token)
    assert await idb(datasette).get(row.id) is None
    assert await cached_count(datasette, row.id) == 0
    with pytest.raises(CredentialNotFound):
        await cred.token()


@pytest.mark.asyncio
async def test_revoke_failure_still_deletes(mock_google):
    datasette = await make_datasette(mock_google)
    row, refresh_token = await add_oauth(datasette, mock_google)
    mock_google.faults.fail("/revoke", 500)

    result = await delete(datasette, ALICE, row.id)

    assert result.revoked is False
    assert result.revoke_error is not None
    assert result.revoke_error.startswith("HTTP 500")
    assert refresh_token not in result.model_dump_json()
    assert len(revoke_calls(mock_google)) == 1
    assert not mock_google.oauth.is_revoked(refresh_token)
    assert await idb(datasette).get(row.id) is None


@pytest.mark.asyncio
async def test_already_revoked_grant_reports_google_error(mock_google):
    # Revoked at Google already (e.g. by the user): Google says invalid_token.
    datasette = await make_datasette(mock_google)
    row, refresh_token = await add_oauth(datasette, mock_google)
    mock_google.oauth.revoke(refresh_token)

    result = await delete(datasette, ALICE, row.id)

    assert result.revoked is False
    assert result.revoke_error is not None
    assert "invalid_token" in result.revoke_error
    assert await idb(datasette).get(row.id) is None


@pytest.mark.asyncio
async def test_undecryptable_oauth_credential_is_still_deleted(mock_google):
    datasette = await make_datasette(mock_google)
    row, _ = await add_oauth(datasette, mock_google)
    # The encryption key was replaced without keeping the old one.
    config = datasette._google_credentials_config
    datasette._google_credentials_config = config.model_copy(
        update={"encryption_key": Fernet.generate_key().decode()}
    )

    result = await delete(datasette, ALICE, row.id)

    assert result.revoked is False
    assert result.revoke_error is not None
    assert "cannot decrypt" in result.revoke_error
    assert not revoke_calls(mock_google)
    assert await idb(datasette).get(row.id) is None


# --- Delete: service account ------------------------------------------------------


@pytest.mark.asyncio
async def test_service_account_delete_returns_key_details(
    mock_google, service_account_keys
):
    datasette = await make_datasette(mock_google)
    info = await add_sa(datasette, service_account_keys)
    cred = await get_credential(datasette, info.id, actor=ALICE, scopes=[SCOPE_SHEETS])
    await cred.token()
    assert await cached_count(datasette, info.id) == 1

    result = await delete(datasette, ALICE, info.id)

    key = service_account_keys["test"]
    assert result == DeleteResult(
        id=info.id,
        type="service_account",
        client_email=SA_TEST,
        private_key_id=key.private_key_id,
        project_id=PROJECT_ID,
        cloud_console_url=(
            "https://console.cloud.google.com/iam-admin/serviceaccounts"
            f"?project={PROJECT_ID}"
        ),
    )
    assert "PRIVATE KEY" not in result.model_dump_json()
    assert not revoke_calls(mock_google)
    assert await idb(datasette).get(info.id) is None
    assert await cached_count(datasette, info.id) == 0
    # acl grants are left behind (no delete-resource API); harmless.
    assert await list_grants(datasette, RESOURCE_TYPE, info.id)


def test_cloud_console_url_encodes_project():
    assert cloud_console_url("a b&c") == (
        "https://console.cloud.google.com/iam-admin/serviceaccounts?project=a+b%26c"
    )


# --- Cache --------------------------------------------------------------------


@pytest.mark.asyncio
async def test_rotate_evicts_cache(mock_google, service_account_keys):
    datasette = await make_datasette(mock_google)
    info = await add_sa(datasette, service_account_keys)
    cred = await get_credential(datasette, info.id, actor=ALICE, scopes=[SCOPE_SHEETS])
    await cred.token()
    assert await cached_count(datasette, info.id) == 1

    new_key = make_service_account(SA_TEST)
    mock_google.tokens.register_service_account(SA_TEST, new_key.public_key)
    await rotate_service_account_key(datasette, ALICE, info.id, raw(new_key))
    assert await cached_count(datasette, info.id) == 0


# --- Events ---------------------------------------------------------------------


def payload(event) -> dict:
    return event.properties() | {"actor": event.actor}


@pytest.mark.asyncio
async def test_service_account_events(mock_google, service_account_keys, events):
    datasette = await make_datasette(mock_google)
    info = await add_sa(datasette, service_account_keys)
    new_key = make_service_account(SA_TEST)
    mock_google.tokens.register_service_account(SA_TEST, new_key.public_key)
    await rotate_service_account_key(datasette, ALICE, info.id, raw(new_key))
    await delete(datasette, ADMIN_ACTOR, info.id)

    common = {
        "credential_id": info.id,
        "credential_type": "service_account",
        "owner_id": "alice",
        "google_email": SA_TEST,
    }
    assert events.names() == [
        "google-credential-created",
        "google-credential-rotated",
        "google-credential-deleted",
    ]
    created, rotated, deleted = events.events
    assert payload(created) == common | {"actor": ALICE}
    assert payload(rotated) == common | {"actor": ALICE}
    assert payload(deleted) == common | {"actor": ADMIN_ACTOR, "revoked": None}


@pytest.mark.asyncio
async def test_oauth_connect_reconnect_delete_events(mock_google, events):
    datasette = await make_datasette(mock_google)
    await connect(datasette, mock_google)
    (row,) = await idb(datasette).list_owned("alice")
    await connect(datasette, mock_google)
    result = await delete(datasette, ALICE, row.id)
    assert result.revoked is True

    common = {
        "credential_id": row.id,
        "credential_type": "google_oauth",
        "owner_id": "alice",
        "google_email": row.google_email,
        "actor": ALICE,
    }
    assert events.names() == [
        "google-credential-created",
        "google-credential-reconnected",
        "google-credential-deleted",
    ]
    created, reconnected, deleted = events.events
    assert payload(created) == common
    assert payload(reconnected) == common
    assert payload(deleted) == common | {"revoked": True}


@pytest.mark.asyncio
async def test_revoke_failure_event_says_not_revoked(mock_google, events):
    datasette = await make_datasette(mock_google)
    row, _ = await add_oauth(datasette, mock_google)
    mock_google.faults.fail("/revoke", 500)
    await delete(datasette, ADMIN_ACTOR, row.id)
    (deleted,) = events.events
    assert deleted.name == "google-credential-deleted"
    assert deleted.revoked is False
    assert deleted.actor == ADMIN_ACTOR


@pytest.mark.asyncio
async def test_oauth_broken_event(mock_google, events):
    datasette = await make_datasette(mock_google)
    row, refresh_token = await add_oauth(datasette, mock_google)
    mock_google.oauth.revoke(refresh_token)
    cred = await get_credential(datasette, row.id, actor=ALICE, scopes=[SCOPE_SHEETS])
    with pytest.raises(CredentialBroken):
        await cred.token()
    (broken,) = events.events
    assert payload(broken) == {
        "credential_id": row.id,
        "credential_type": "google_oauth",
        "owner_id": "alice",
        "google_email": "user@example.com",
        "detail": BROKEN_DETAIL,
        "actor": ALICE,
    }
    # Already broken: the broker refuses before Google, so no second event.
    with pytest.raises(CredentialBroken):
        await cred.token()
    assert len(events.events) == 1


async def add_unregistered_sa(datasette, service_account_keys):
    """A service account whose key Google no longer accepts."""
    key = parse_key(raw(service_account_keys["unregistered"]))
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


@pytest.mark.asyncio
async def test_service_account_broken_event(mock_google, service_account_keys, events):
    datasette = await make_datasette(mock_google)
    row = await add_unregistered_sa(datasette, service_account_keys)
    await share(datasette, row.id, "User")
    cred = await get_credential(datasette, row.id, actor=BOB, scopes=[SCOPE_SHEETS])
    with pytest.raises(CredentialBroken):
        await cred.token()
    (broken,) = events.events
    assert broken.name == "google-credential-broken"
    assert broken.detail == SA_BROKEN_DETAIL
    assert broken.actor == BOB
    assert broken.owner_id == "alice"


@pytest.mark.asyncio
async def test_no_broken_event_when_compare_and_swap_loses(
    mock_google, service_account_keys, events
):
    datasette = await make_datasette(mock_google)
    info = await add_sa(datasette, service_account_keys)
    stale = await idb(datasette).get(info.id)
    assert stale is not None
    new_key = make_service_account(SA_TEST)
    mock_google.tokens.register_service_account(SA_TEST, new_key.public_key)
    await rotate_service_account_key(datasette, ALICE, info.id, raw(new_key))
    events.events.clear()

    assert not await mark_broken(datasette, stale, "rejected", actor_id="alice")
    assert events.events == []
    current = await idb(datasette).get(info.id)
    assert current is not None and current.status == "ok"

    assert await mark_broken(datasette, current, "rejected", actor_id="alice")
    assert events.names() == ["google-credential-broken"]


@pytest.mark.asyncio
async def test_no_broken_event_when_key_rotated_during_mint(
    mock_google, service_account_keys, monkeypatch, events
):
    from datasette_google_credentials import broker

    datasette = await make_datasette(mock_google)
    row = await add_unregistered_sa(datasette, service_account_keys)
    cred = await get_credential(datasette, row.id, actor=ALICE, scopes=[SCOPE_SHEETS])
    real_mint = broker.mint_service_account_token

    async def rotate_then_mint(*args, **kwargs):
        good = parse_key(raw(service_account_keys["test"]))
        await idb(datasette).update_secret(
            row.id, encrypt_secret(datasette, good.to_secret()), actor_id="alice"
        )
        return await real_mint(*args, **kwargs)

    monkeypatch.setattr(broker, "mint_service_account_token", rotate_then_mint)
    with pytest.raises(CredentialChanged):
        await cred.token()
    assert events.events == []


@pytest.mark.asyncio
async def test_no_secrets_in_any_event(mock_google, service_account_keys, events):
    datasette = await make_datasette(mock_google)
    secrets: list[str] = []

    # Service account: add, use, rotate, delete.
    info = await add_sa(datasette, service_account_keys)
    row = await idb(datasette).get(info.id)
    assert row is not None
    cred = await get_credential(datasette, info.id, actor=ALICE, scopes=[SCOPE_SHEETS])
    secrets.append(await cred.token())
    new_key = make_service_account(SA_TEST)
    mock_google.tokens.register_service_account(SA_TEST, new_key.public_key)
    await rotate_service_account_key(datasette, ALICE, info.id, raw(new_key))
    for key in (service_account_keys["test"], new_key):
        secrets += [key.private_key_pem, key.private_key_pem.splitlines()[1]]
    secrets.append(row.secret_encrypted.decode())
    await delete(datasette, ALICE, info.id)

    # OAuth: connect, reconnect, use, break, delete.
    await connect(datasette, mock_google)
    await connect(datasette, mock_google)
    (oauth_row,) = await idb(datasette).list_owned("alice")
    refresh_token = (await decrypt_credential(datasette, oauth_row))["refresh_token"]
    secrets += [refresh_token, oauth_row.secret_encrypted.decode()]
    cred = await get_credential(
        datasette, oauth_row.id, actor=ALICE, scopes=[SCOPE_SHEETS]
    )
    secrets.append(await cred.token())
    mock_google.oauth.revoke(refresh_token)
    get_token_cache(datasette).evict(oauth_row.id)
    with pytest.raises(CredentialBroken):
        await cred.token()
    await delete(datasette, ALICE, oauth_row.id)

    # Broken SA too.
    broken_sa = await add_unregistered_sa(datasette, service_account_keys)
    cred = await get_credential(
        datasette, broken_sa.id, actor=ALICE, scopes=[SCOPE_SHEETS]
    )
    with pytest.raises(CredentialBroken):
        await cred.token()

    assert set(events.names()) == EVENT_NAMES
    dumped = events.dumps()
    for secret in secrets:
        assert secret and secret not in dumped
    assert "PRIVATE KEY" not in dumped
    assert "ya29." not in dumped
