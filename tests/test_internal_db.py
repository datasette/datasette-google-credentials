import sqlite3

import pytest
import pytest_asyncio
from datasette.app import Datasette
from sqlite_utils import Database as SqliteUtilsDatabase

from datasette_google_auth.internal_db import (
    TABLE,
    CredentialRow,
    InternalDB,
)
from datasette_google_auth.internal_migrations import (
    internal_migrations,
    m001_credentials,
)

# Stand-ins for Fernet tokens; this layer stores bytes as given.
SECRET = b"encrypted-secret-1"
SECRET_2 = b"encrypted-secret-2"


@pytest_asyncio.fixture
async def datasette():
    datasette = Datasette(memory=True)
    await datasette.invoke_startup()
    return datasette


@pytest.fixture
def idb(datasette):
    return InternalDB(datasette.get_internal_database())


async def add_sa(idb, owner_id="alice", label="SA", **kwargs):
    return await idb.insert(
        type="service_account",
        label=label,
        owner_id=owner_id,
        secret_encrypted=SECRET,
        created_by=owner_id,
        google_subject="1234567890",
        google_email="sa@project.iam.gserviceaccount.com",
        **kwargs,
    )


async def connect(idb, owner_id="alice", subject="sub-1", **kwargs):
    values = {
        "google_email": "alice@example.com",
        "label": "alice@example.com",
        "scopes": ["openid", "email"],
        "secret_encrypted": SECRET,
        "actor_id": owner_id,
    }
    values.update(kwargs)
    return await idb.upsert_oauth(owner_id, subject, **values)


# ---------------------------------------------------------------- migrations


@pytest.mark.asyncio
async def test_startup_creates_table_and_indexes(datasette):
    db = datasette.get_internal_database()
    rows = (
        await db.execute(
            "SELECT type, name, sql FROM sqlite_master WHERE tbl_name = ?", [TABLE]
        )
    ).rows
    by_name = {row["name"]: row for row in rows}
    assert by_name[TABLE]["type"] == "table"
    unique = by_name["datasette_google_auth_credentials_oauth_unique"]
    assert "UNIQUE" in unique["sql"]
    assert "WHERE type = 'google_oauth'" in unique["sql"]
    assert by_name["datasette_google_auth_credentials_owner"]["type"] == "index"
    applied = (
        await db.execute(
            "SELECT name FROM _sqlite_migrations WHERE migration_set = ?",
            ["datasette-google-auth.internal"],
        )
    ).rows
    assert [row["name"] for row in applied] == ["m001_credentials"]


@pytest.mark.asyncio
async def test_migrations_apply_twice(datasette):
    db = datasette.get_internal_database()

    def apply_again(conn):
        sqlite_utils_db = SqliteUtilsDatabase(conn)
        internal_migrations.apply(sqlite_utils_db)
        # And the migration body itself is re-runnable (IF NOT EXISTS)
        m001_credentials(sqlite_utils_db)
        return internal_migrations.applied(sqlite_utils_db)

    applied = await db.execute_write_fn(apply_again)
    assert [m.name for m in applied] == ["m001_credentials"]


@pytest.mark.asyncio
async def test_restart_with_persistent_internal_db(tmp_path):
    internal = str(tmp_path / "internal.db")
    first = Datasette(memory=True, internal=internal)
    await first.invoke_startup()
    row = await add_sa(InternalDB(first.get_internal_database()))
    first.close()

    second = Datasette(memory=True, internal=internal)
    await second.invoke_startup()
    assert await InternalDB(second.get_internal_database()).get(row.id) == row
    second.close()


@pytest.mark.asyncio
async def test_type_has_no_check_constraint_but_status_does(datasette):
    # New credential types must not need a table rebuild; Python validates.
    db = datasette.get_internal_database()

    def insert_raw(type, status):
        def insert_raw_row(conn):
            conn.execute(
                f"INSERT INTO {TABLE} (id, type, label, owner_id, secret_encrypted,"
                " created_by, status) VALUES (?, ?, 'x', 'o', x'00', 'o', ?)",
                [f"{type}-{status}", type, status],
            )

        return insert_raw_row

    await db.execute_write_fn(insert_raw("api_key", "ok"))
    with pytest.raises(sqlite3.IntegrityError):
        await db.execute_write_fn(insert_raw("service_account", "weird"))


@pytest.mark.asyncio
async def test_insert_rejects_unknown_type(idb):
    with pytest.raises(ValueError, match="api_key"):
        await idb.insert(
            type="api_key",
            label="x",
            owner_id="alice",
            secret_encrypted=SECRET,
            created_by="alice",
        )
    assert await idb.list_all() == []


# ---------------------------------------------------------------- reads


@pytest.mark.asyncio
async def test_insert_and_get(idb):
    row = await add_sa(idb, scopes=None, label="Reporting SA")
    assert isinstance(row, CredentialRow)
    assert row.type == "service_account"
    assert row.label == "Reporting SA"
    assert row.owner_id == "alice"
    assert row.google_email == "sa@project.iam.gserviceaccount.com"
    assert row.scopes == []
    assert row.secret_encrypted == SECRET
    assert row.status == "ok"
    assert row.status_detail is None
    assert row.created_by == "alice"
    assert row.created_at.endswith("Z")
    assert row.updated_at is None
    assert row.last_used_at is None
    assert await idb.get(row.id) == row
    assert await idb.get("missing") is None


@pytest.mark.asyncio
async def test_list_owned_by_ids_and_all(idb):
    a1 = await add_sa(idb, owner_id="alice", label="a1")
    b1 = await add_sa(idb, owner_id="bob", label="b1")
    a2, _ = await connect(idb, owner_id="alice")

    assert [r.id for r in await idb.list_owned("alice")] == [a1.id, a2.id]
    assert [r.id for r in await idb.list_owned("bob")] == [b1.id]
    assert await idb.list_owned("carol") == []

    assert [r.id for r in await idb.list_by_ids([a2.id, "nope", b1.id])] == [
        b1.id,
        a2.id,
    ]
    assert await idb.list_by_ids([]) == []

    assert [r.id for r in await idb.list_all()] == [a1.id, b1.id, a2.id]


@pytest.mark.asyncio
async def test_ulids_sort_in_creation_order(idb):
    created = [(await add_sa(idb, label=str(i))).id for i in range(50)]
    assert all(len(id) == 26 for id in created)
    assert created == sorted(created)
    assert len(set(created)) == 50
    assert [r.id for r in await idb.list_all()] == created
    assert [r.label for r in await idb.list_all()] == [str(i) for i in range(50)]


def test_secret_never_dumped_or_repr():
    row = CredentialRow.model_validate(
        {
            "id": "01J0000000000000000000000",
            "type": "google_oauth",
            "label": "l",
            "owner_id": "o",
            "google_subject": "s",
            "google_email": None,
            "scopes": '["openid"]',
            "secret_encrypted": SECRET,
            "status": "ok",
            "status_detail": None,
            "last_used_at": None,
            "last_used_by": None,
            "created_at": "2026-01-01T00:00:00.000Z",
            "created_by": "o",
            "updated_at": None,
            "updated_by": None,
        }
    )
    assert row.scopes == ["openid"]
    assert "secret_encrypted" not in row.model_dump()
    assert "secret_encrypted" not in row.model_dump_json()
    assert SECRET.decode() not in repr(row)
    assert SECRET.decode() not in str(row)


# ---------------------------------------------------------------- upsert_oauth


@pytest.mark.asyncio
async def test_upsert_oauth_dedupes_by_owner_and_subject(idb):
    first, created = await connect(idb, scopes=["openid", "email"])
    assert created
    assert first.type == "google_oauth"
    assert first.google_subject == "sub-1"
    assert first.updated_at is None

    again, created = await connect(
        idb,
        google_email="alice.new@example.com",
        label="ignored on reconnect",
        scopes=["openid", "email", "https://www.googleapis.com/auth/spreadsheets"],
        secret_encrypted=SECRET_2,
    )
    assert not created
    assert again.id == first.id
    assert again.label == "alice@example.com"
    assert again.google_email == "alice.new@example.com"
    assert again.scopes == [
        "openid",
        "email",
        "https://www.googleapis.com/auth/spreadsheets",
    ]
    assert again.secret_encrypted == SECRET_2
    assert again.created_at == first.created_at
    assert again.updated_at is not None
    assert again.updated_by == "alice"
    assert [r.id for r in await idb.list_owned("alice")] == [first.id]


@pytest.mark.asyncio
async def test_upsert_oauth_not_deduped_across_owners_or_subjects(idb):
    alice, _ = await connect(idb, owner_id="alice", subject="sub-1")
    bob, created = await connect(idb, owner_id="bob", subject="sub-1")
    assert created
    alice_second, created = await connect(idb, owner_id="alice", subject="sub-2")
    assert created
    assert len({alice.id, bob.id, alice_second.id}) == 3
    assert len(await idb.list_all()) == 3


@pytest.mark.asyncio
async def test_upsert_oauth_ignores_service_accounts(idb):
    # The unique index is partial: SA rows never collide with OAuth rows.
    sa = await add_sa(idb, owner_id="alice")
    oauth, created = await connect(idb, owner_id="alice", subject=sa.google_subject)
    assert created
    assert oauth.id != sa.id
    await add_sa(idb, owner_id="alice")
    assert len(await idb.list_owned("alice")) == 3


@pytest.mark.asyncio
async def test_upsert_oauth_reconnect_clears_broken(idb):
    row, _ = await connect(idb)
    await idb.mark_broken(row.id, "invalid_grant")
    again, _ = await connect(idb, secret_encrypted=SECRET_2)
    assert again.status == "ok"
    assert again.status_detail is None


@pytest.mark.asyncio
async def test_upsert_oauth_requires_subject(idb):
    with pytest.raises(ValueError):
        await connect(idb, subject="")


@pytest.mark.asyncio
async def test_plain_insert_of_duplicate_oauth_violates_index(idb):
    row, _ = await connect(idb)
    with pytest.raises(sqlite3.IntegrityError):
        await idb.insert(
            type="google_oauth",
            label="dup",
            owner_id="alice",
            secret_encrypted=SECRET,
            created_by="alice",
            google_subject=row.google_subject,
        )


# ---------------------------------------------------------------- updates


@pytest.mark.asyncio
async def test_mark_broken_and_mark_ok(idb):
    row = await add_sa(idb)
    assert await idb.mark_broken(row.id, "Token refresh failed: invalid_grant")
    broken = await idb.get(row.id)
    assert broken.status == "broken"
    assert broken.status_detail == "Token refresh failed: invalid_grant"

    assert await idb.mark_ok(row.id)
    ok = await idb.get(row.id)
    assert ok.status == "ok"
    assert ok.status_detail is None

    assert not await idb.mark_broken("missing", "x")
    assert not await idb.mark_ok("missing")


@pytest.mark.asyncio
async def test_update_secret(idb):
    row = await add_sa(idb)
    await idb.mark_broken(row.id, "key deleted")
    assert await idb.update_secret(row.id, SECRET_2, actor_id="bob")
    updated = await idb.get(row.id)
    assert updated.secret_encrypted == SECRET_2
    assert updated.status == "ok"
    assert updated.status_detail is None
    assert updated.updated_by == "bob"
    assert updated.updated_at is not None
    assert not await idb.update_secret("missing", SECRET_2, actor_id="bob")


@pytest.mark.asyncio
async def test_reencrypt_secret(idb):
    row = await add_sa(idb)
    await idb.mark_broken(row.id, "key deleted")
    # Only swaps if the row still holds the old ciphertext
    assert not await idb.reencrypt_secret(row.id, old=b"stale", new=SECRET_2)
    assert (await idb.get(row.id)).secret_encrypted == SECRET
    assert await idb.reencrypt_secret(row.id, old=SECRET, new=SECRET_2)
    after = await idb.get(row.id)
    assert after.secret_encrypted == SECRET_2
    # Not an edit: status and updated_* untouched
    assert after.status == "broken"
    assert after.updated_at is None
    assert after.updated_by is None
    assert not await idb.reencrypt_secret("missing", old=SECRET, new=SECRET_2)


@pytest.mark.asyncio
async def test_rename(idb):
    row = await add_sa(idb)
    assert await idb.rename(row.id, "New name", actor_id="bob")
    renamed = await idb.get(row.id)
    assert renamed.label == "New name"
    assert renamed.updated_by == "bob"
    assert renamed.secret_encrypted == SECRET
    assert not await idb.rename("missing", "x", actor_id="bob")


@pytest.mark.asyncio
async def test_touch_used(idb):
    row = await add_sa(idb)
    assert await idb.touch_used(row.id, "bob")
    used = await idb.get(row.id)
    assert used.last_used_by == "bob"
    assert used.last_used_at is not None
    # Use is not an edit
    assert used.updated_at is None
    assert not await idb.touch_used("missing", "bob")


@pytest.mark.asyncio
async def test_delete(idb):
    row = await add_sa(idb)
    other = await add_sa(idb)
    assert await idb.delete(row.id)
    assert await idb.get(row.id) is None
    assert await idb.get(other.id) is not None
    assert not await idb.delete(row.id)


@pytest.mark.asyncio
async def test_writes_use_named_functions(idb, monkeypatch):
    # Datasette labels write spans by the callback's __qualname__.
    names = []
    original = idb.db.execute_write_fn

    async def spy(fn, *args, **kwargs):
        names.append(fn.__qualname__)
        return await original(fn, *args, **kwargs)

    monkeypatch.setattr(idb.db, "execute_write_fn", spy)
    row = await add_sa(idb)
    oauth, _ = await connect(idb)
    await idb.update_secret(row.id, SECRET_2, actor_id="alice")
    await idb.rename(row.id, "x", actor_id="alice")
    await idb.mark_broken(row.id, "x")
    await idb.mark_ok(row.id)
    await idb.touch_used(row.id, "alice")
    await idb.delete(oauth.id)
    assert [name.rsplit(".", 1)[-1] for name in names] == [
        "insert_credential",
        "upsert_oauth_credential",
        "update_credential_secret",
        "rename_credential",
        "mark_credential_broken",
        "mark_credential_ok",
        "touch_credential_used",
        "delete_credential",
    ]
