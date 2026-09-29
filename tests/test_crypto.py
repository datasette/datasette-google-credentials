import asyncio
import base64
import json
import sqlite3

import pytest
from click.testing import CliRunner
from cryptography.fernet import Fernet, InvalidToken
from datasette.app import Datasette
from datasette.cli import cli
from datasette.utils import StartupError

from datasette_google_auth.crypto import (
    InvalidEncryptionKey,
    SecretBox,
    decrypt_credential,
    encrypt_secret,
    get_box,
    require_box,
    rotate_all_credentials,
)
from datasette_google_auth.errors import (
    CredentialUndecryptable,
    EncryptionNotConfigured,
    GoogleAuthError,
)
from datasette_google_auth.internal_db import TABLE, InternalDB

KEY_NEW = Fernet.generate_key().decode()
KEY_OLD = Fernet.generate_key().decode()
KEY_OTHER = Fernet.generate_key().decode()

# Fake but realistically shaped secrets, for the "never stored in plaintext"
# checks.
PRIVATE_KEY = (
    "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC-fake-key-body"
    "\n-----END PRIVATE KEY-----\n"
)
REFRESH_TOKEN = "1//0fake-refresh-token-Zq9xWv"
SA_SECRET = {
    "client_email": "sa@project.iam.gserviceaccount.com",
    "private_key": PRIVATE_KEY,
    "private_key_id": "abc123",
    "project_id": "project",
}
OAUTH_SECRET = {"refresh_token": REFRESH_TOKEN}


def plugin_config(encryption_key):
    return {"plugins": {"datasette-google-auth": {"encryption-key": encryption_key}}}


async def started(encryption_key=None, internal=None):
    config = plugin_config(encryption_key) if encryption_key is not None else {}
    datasette = Datasette(memory=True, internal=internal, config=config)
    await datasette.invoke_startup()
    return datasette


async def add_sa(datasette, secret=SA_SECRET):
    return await InternalDB(datasette.get_internal_database()).insert(
        type="service_account",
        label="SA",
        owner_id="alice",
        secret_encrypted=encrypt_secret(datasette, secret),
        created_by="alice",
        google_subject="1234567890",
        google_email=secret["client_email"],
    )


# ---------------------------------------------------------------- SecretBox


def test_round_trip():
    box = SecretBox([KEY_NEW])
    token = box.encrypt(SA_SECRET)
    assert isinstance(token, bytes)
    assert box.decrypt(token) == SA_SECRET
    assert not box.needs_rotation(token)
    # Fresh IV each time
    assert box.encrypt(SA_SECRET) != token


def test_multifernet_decrypts_old_key_and_rotates():
    old_token = SecretBox([KEY_OLD]).encrypt(OAUTH_SECRET)
    box = SecretBox([KEY_NEW, KEY_OLD])
    assert box.decrypt(old_token) == OAUTH_SECRET
    assert box.needs_rotation(old_token)

    rotated = box.rotate(old_token)
    assert not box.needs_rotation(rotated)
    # Now readable with the new key alone
    assert SecretBox([KEY_NEW]).decrypt(rotated) == OAUTH_SECRET
    with pytest.raises(InvalidToken):
        SecretBox([KEY_OLD]).decrypt(rotated)

    # New writes use the first key
    assert SecretBox([KEY_NEW]).decrypt(box.encrypt(SA_SECRET)) == SA_SECRET


def test_wrong_key_raises_invalid_token():
    token = SecretBox([KEY_OLD]).encrypt(SA_SECRET)
    box = SecretBox([KEY_NEW, KEY_OTHER])
    with pytest.raises(InvalidToken):
        box.decrypt(token)
    with pytest.raises(InvalidToken):
        box.needs_rotation(token)
    with pytest.raises(InvalidToken):
        box.rotate(token)


def test_repr_hides_keys():
    assert KEY_NEW not in repr(SecretBox([KEY_NEW]))


@pytest.mark.parametrize(
    "keys,where",
    [
        (["not-a-fernet-key"], "key is"),
        # Valid base64, wrong length
        ([base64.urlsafe_b64encode(b"x" * 31).decode()], "key is"),
        (["ключ-не-ascii"], "key is"),
        ([KEY_NEW, "not-a-fernet-key"], "key 2 of 2"),
    ],
)
def test_invalid_key_material(keys, where):
    with pytest.raises(InvalidEncryptionKey) as excinfo:
        SecretBox(keys)
    message = str(excinfo.value)
    assert where in message
    assert "generate-key" in message
    for key in keys:
        assert key not in message
    assert excinfo.value.__cause__ is None
    assert excinfo.value.__suppress_context__


# ---------------------------------------------------------------- startup


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "encryption_key,where",
    [
        ("not-a-fernet-key-but-a-secret", "encryption-key: key is"),
        ([KEY_NEW, "not-a-fernet-key-but-a-secret"], "encryption-key: key 2 of 2"),
    ],
)
async def test_invalid_key_fails_startup(encryption_key, where):
    with pytest.raises(StartupError) as excinfo:
        await started(encryption_key)
    message = str(excinfo.value)
    assert "datasette-google-auth" in message
    assert where in message
    assert "not-a-fernet-key-but-a-secret" not in message
    assert KEY_NEW not in message
    assert excinfo.value.__cause__ is None
    assert excinfo.value.__suppress_context__


@pytest.mark.asyncio
async def test_valid_keys_build_box():
    datasette = await started([KEY_NEW, KEY_OLD])
    box = get_box(datasette)
    assert isinstance(box, SecretBox)
    assert SecretBox([KEY_NEW]).decrypt(box.encrypt({"a": 1})) == {"a": 1}


# ---------------------------------------------------------------- no key


@pytest.mark.asyncio
@pytest.mark.parametrize("encryption_key", [None, "", []])
async def test_no_key_gives_none_and_writes_refuse(encryption_key):
    datasette = await started(encryption_key)
    assert get_box(datasette) is None
    message = "datasette-google-auth needs `encryption-key` configured"
    with pytest.raises(EncryptionNotConfigured, match=message):
        require_box(datasette)
    with pytest.raises(EncryptionNotConfigured, match=message):
        encrypt_secret(datasette, SA_SECRET)
    with pytest.raises(EncryptionNotConfigured):
        await rotate_all_credentials(datasette)
    assert issubclass(EncryptionNotConfigured, GoogleAuthError)


@pytest.mark.asyncio
async def test_key_removed_after_credentials_exist(tmp_path):
    # Startup still works (no crash loop); reading gives a clear error.
    internal = str(tmp_path / "internal.db")
    first = await started(KEY_NEW, internal=internal)
    row = await add_sa(first)
    first.close()

    second = await started(None, internal=internal)
    with pytest.raises(EncryptionNotConfigured):
        await decrypt_credential(second, row)
    second.close()


# ---------------------------------------------------------------- decrypt_credential


@pytest.mark.asyncio
async def test_decrypt_credential():
    datasette = await started(KEY_NEW)
    row = await add_sa(datasette)
    assert await decrypt_credential(datasette, row) == SA_SECRET
    # Nothing to rotate: the row is untouched
    idb = InternalDB(datasette.get_internal_database())
    assert (await idb.get(row.id)).secret_encrypted == row.secret_encrypted


@pytest.mark.asyncio
async def test_lazy_rotation_on_decrypt(tmp_path):
    internal = str(tmp_path / "internal.db")
    old = await started(KEY_OLD, internal=internal)
    row = await add_sa(old)
    old.close()

    datasette = await started([KEY_NEW, KEY_OLD], internal=internal)
    idb = InternalDB(datasette.get_internal_database())
    assert await decrypt_credential(datasette, row) == SA_SECRET

    after = await idb.get(row.id)
    assert after.secret_encrypted != row.secret_encrypted
    assert SecretBox([KEY_NEW]).decrypt(after.secret_encrypted) == SA_SECRET
    # Re-encryption is not an edit
    assert after.updated_at is None
    assert after.updated_by is None
    assert after.status == "ok"

    # Reading the rotated row doesn't write again
    assert await decrypt_credential(datasette, after) == SA_SECRET
    assert (await idb.get(row.id)).secret_encrypted == after.secret_encrypted


@pytest.mark.asyncio
async def test_lazy_rotation_keeps_broken_status(tmp_path):
    internal = str(tmp_path / "internal.db")
    old = await started(KEY_OLD, internal=internal)
    row = await add_sa(old)
    await InternalDB(old.get_internal_database()).mark_broken(row.id, "key deleted")
    old.close()

    datasette = await started([KEY_NEW, KEY_OLD], internal=internal)
    await decrypt_credential(datasette, row)
    after = await InternalDB(datasette.get_internal_database()).get(row.id)
    assert after.status == "broken"
    assert after.status_detail == "key deleted"


@pytest.mark.asyncio
async def test_lazy_rotation_never_overwrites_a_concurrent_update(tmp_path):
    internal = str(tmp_path / "internal.db")
    old = await started(KEY_OLD, internal=internal)
    stale_row = await add_sa(old)
    old.close()

    datasette = await started([KEY_NEW, KEY_OLD], internal=internal)
    idb = InternalDB(datasette.get_internal_database())
    replacement = encrypt_secret(datasette, {**SA_SECRET, "private_key_id": "new"})
    await idb.update_secret(stale_row.id, replacement, actor_id="bob")

    # A reader still holding the pre-update row decrypts it...
    assert await decrypt_credential(datasette, stale_row) == SA_SECRET
    # ...but its re-encryption must not clobber the new secret
    assert (await idb.get(stale_row.id)).secret_encrypted == replacement


@pytest.mark.asyncio
async def test_wrong_key_maps_to_credential_error(tmp_path):
    internal = str(tmp_path / "internal.db")
    old = await started(KEY_OLD, internal=internal)
    row = await add_sa(old)
    old.close()

    datasette = await started(KEY_NEW, internal=internal)
    with pytest.raises(CredentialUndecryptable) as excinfo:
        await decrypt_credential(datasette, row)
    error = excinfo.value
    assert isinstance(error, GoogleAuthError)
    assert error.credential_id == row.id
    message = str(error)
    assert "cannot decrypt — was encryption-key changed?" in message
    assert row.secret_encrypted.decode() not in message
    assert row.secret_encrypted.decode()[:20] not in message
    assert error.__cause__ is None
    assert error.__suppress_context__
    # Left alone, so restoring the old key fixes it
    idb = InternalDB(datasette.get_internal_database())
    after = await idb.get(row.id)
    assert after.secret_encrypted == row.secret_encrypted
    assert after.status == "ok"


# ---------------------------------------------------------------- at rest


@pytest.mark.asyncio
async def test_raw_row_is_encrypted(tmp_path):
    internal = str(tmp_path / "internal.db")
    datasette = await started(KEY_NEW, internal=internal)
    sa = await add_sa(datasette)
    oauth, _ = await InternalDB(datasette.get_internal_database()).upsert_oauth(
        "alice",
        "sub-1",
        google_email="alice@example.com",
        label="alice@example.com",
        scopes=["openid", "email"],
        secret_encrypted=encrypt_secret(datasette, OAUTH_SECRET),
        actor_id="alice",
    )
    datasette.close()

    # Straight from the file, bypassing the plugin entirely
    conn = sqlite3.connect(internal)
    raw_rows = dict(conn.execute(f"SELECT id, secret_encrypted FROM {TABLE}"))
    whole_file = open(internal, "rb").read()
    conn.close()
    assert set(raw_rows) == {sa.id, oauth.id}

    needles = [
        PRIVATE_KEY,
        "BEGIN PRIVATE KEY",
        "fake-key-body",
        "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC",
        REFRESH_TOKEN,
        "fake-refresh-token",
        "private_key",
        "refresh_token",
    ]
    for raw in [*raw_rows.values(), whole_file]:
        raw = bytes(raw)
        for needle in needles:
            assert needle.encode() not in raw
            assert json.dumps(needle)[1:-1].encode() not in raw
    for raw in raw_rows.values():
        # A Fernet token (version byte 0x80, base64-encoded)
        assert bytes(raw).startswith(b"gAAAAA")
    # And it does decrypt back
    box = SecretBox([KEY_NEW])
    assert box.decrypt(raw_rows[sa.id]) == SA_SECRET
    assert box.decrypt(raw_rows[oauth.id]) == OAUTH_SECRET


# ---------------------------------------------------------------- CLI


def test_cli_generate_key():
    runner = CliRunner()
    result = runner.invoke(cli, ["google-auth", "generate-key"])
    assert result.exit_code == 0, result.output
    key = result.output.strip()
    assert result.output == key + "\n"
    # A valid Fernet key
    SecretBox([key])
    assert len(base64.urlsafe_b64decode(key)) == 32
    again = runner.invoke(cli, ["google-auth", "generate-key"]).output.strip()
    assert again != key


def test_cli_group_help():
    result = CliRunner().invoke(cli, ["google-auth", "--help"])
    assert result.exit_code == 0
    assert "generate-key" in result.output
    assert "rotate-keys" in result.output


def seed_old_key_rows(internal, count=2):
    async def seed():
        datasette = await started(KEY_OLD, internal=internal)
        rows = [await add_sa(datasette) for _ in range(count)]
        datasette.close()
        return rows

    return asyncio.run(seed())


def read_secrets(internal):
    conn = sqlite3.connect(internal)
    rows = dict(conn.execute(f"SELECT id, secret_encrypted FROM {TABLE}"))
    conn.close()
    return rows


def write_config(tmp_path, encryption_key):
    path = tmp_path / "datasette.json"
    path.write_text(json.dumps(plugin_config(encryption_key)))
    return str(path)


def test_cli_rotate_keys_with_config_file(tmp_path):
    internal = str(tmp_path / "internal.db")
    rows = seed_old_key_rows(internal)
    config = write_config(tmp_path, [KEY_NEW, KEY_OLD])

    result = CliRunner().invoke(
        cli, ["google-auth", "rotate-keys", "--internal", internal, "-c", config]
    )
    assert result.exit_code == 0, result.output
    assert "Re-encrypted 2 credential(s)" in result.output
    assert "0 already current" in result.output
    new_only = SecretBox([KEY_NEW])
    secrets = read_secrets(internal)
    for row in rows:
        assert new_only.decrypt(secrets[row.id]) == SA_SECRET
    for key in (KEY_NEW, KEY_OLD):
        assert key not in result.output

    # Running again is a no-op
    again = CliRunner().invoke(
        cli, ["google-auth", "rotate-keys", "--internal", internal, "-c", config]
    )
    assert again.exit_code == 0, again.output
    assert "Re-encrypted 0 credential(s)" in again.output
    assert "2 already current" in again.output
    assert read_secrets(internal) == secrets


def test_cli_rotate_keys_with_settings_and_env(tmp_path, monkeypatch):
    internal = str(tmp_path / "internal.db")
    rows = seed_old_key_rows(internal, count=1)
    monkeypatch.setenv("TEST_GOOGLE_AUTH_NEW", KEY_NEW)
    monkeypatch.setenv("TEST_GOOGLE_AUTH_OLD", KEY_OLD)
    result = CliRunner().invoke(
        cli,
        [
            "google-auth",
            "rotate-keys",
            "--internal",
            internal,
            "-s",
            "plugins.datasette-google-auth.encryption-key",
            json.dumps(
                [{"$env": "TEST_GOOGLE_AUTH_NEW"}, {"$env": "TEST_GOOGLE_AUTH_OLD"}]
            ),
        ],
    )
    assert result.exit_code == 0, result.output
    assert "Re-encrypted 1 credential(s)" in result.output
    assert SecretBox([KEY_NEW]).decrypt(read_secrets(internal)[rows[0].id]) == SA_SECRET


def test_cli_rotate_keys_reports_undecryptable(tmp_path):
    internal = str(tmp_path / "internal.db")
    rows = seed_old_key_rows(internal, count=1)
    before = read_secrets(internal)
    config = write_config(tmp_path, [KEY_NEW, KEY_OTHER])
    result = CliRunner().invoke(
        cli, ["google-auth", "rotate-keys", "--internal", internal, "-c", config]
    )
    assert result.exit_code == 1
    assert "1 credential(s) could not be decrypted" in result.output
    assert rows[0].id in result.output
    assert before[rows[0].id].decode() not in result.output
    assert read_secrets(internal) == before


def test_cli_rotate_keys_refuses_without_key(tmp_path):
    internal = str(tmp_path / "internal.db")
    seed_old_key_rows(internal, count=1)
    result = CliRunner().invoke(
        cli, ["google-auth", "rotate-keys", "--internal", internal]
    )
    assert result.exit_code == 1
    assert "needs `encryption-key` configured" in result.output


def test_cli_rotate_keys_bad_key_never_echoed(tmp_path):
    internal = str(tmp_path / "internal.db")
    seed_old_key_rows(internal, count=1)
    config = write_config(tmp_path, [KEY_NEW, "not-a-fernet-key-but-a-secret"])
    result = CliRunner().invoke(
        cli, ["google-auth", "rotate-keys", "--internal", internal, "-c", config]
    )
    assert result.exit_code == 1
    assert "encryption-key: key 2 of 2 is not a valid Fernet key" in result.output
    assert "not-a-fernet-key-but-a-secret" not in result.output
    assert KEY_NEW not in result.output


def test_cli_rotate_keys_requires_existing_internal_db(tmp_path):
    result = CliRunner().invoke(
        cli,
        ["google-auth", "rotate-keys", "--internal", str(tmp_path / "missing.db")],
    )
    assert result.exit_code == 2
    assert not (tmp_path / "missing.db").exists()
