"""Data access for the credentials table in Datasette's internal DB.

Reads use ``db.execute()``; writes use ``execute_write_fn()`` with named
inner functions, because Datasette labels each write's ``db.query`` span with
the callback's ``__qualname__`` (a lambda would show up as ``<lambda>``).

This layer never decrypts anything. ``CredentialRow.secret_encrypted`` holds
the Fernet token as stored; it is excluded from ``model_dump()`` and ``repr``
so a row can't leak it into a response or a log by accident.

No permission checks here: callers (the broker, routes) decide who may see or
change a credential.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Literal, get_args

from pydantic import BaseModel, ConfigDict, Field, field_validator
from ulid import ULID

if TYPE_CHECKING:
    from datasette.database import Database

TABLE = "datasette_google_credentials"

# The schema leaves `type` unconstrained so new types need no table rebuild;
# this is the only place the allowed values live.
CredentialType = Literal["service_account", "google_oauth"]
CREDENTIAL_TYPES: tuple[str, ...] = get_args(CredentialType)
CredentialStatus = Literal["ok", "broken"]

NOW = "strftime('%Y-%m-%dT%H:%M:%fZ','now')"


class CredentialRow(BaseModel):
    """One row of ``datasette_google_credentials``."""

    model_config = ConfigDict(frozen=True)

    id: str
    type: CredentialType
    label: str
    owner_id: str
    google_subject: str | None
    google_email: str | None
    scopes: list[str]
    secret_encrypted: bytes = Field(repr=False, exclude=True)
    status: CredentialStatus
    status_detail: str | None
    last_used_at: str | None
    last_used_by: str | None
    created_at: str
    created_by: str
    updated_at: str | None
    updated_by: str | None

    @field_validator("scopes", mode="before")
    @classmethod
    def _parse_scopes(cls, value):
        if isinstance(value, str):
            return json.loads(value)
        return value


def validate_type(type: str) -> None:
    if type not in CREDENTIAL_TYPES:
        raise ValueError(f"Unknown credential type: {type!r}")


class InternalDB:
    def __init__(self, internal_db: Database):
        self.db = internal_db

    # ------------------------------------------------------------------ reads

    async def get(self, id: str) -> CredentialRow | None:
        result = await self.db.execute(f"SELECT * FROM {TABLE} WHERE id = ?", [id])
        row = result.first()
        return CredentialRow.model_validate(dict(row)) if row else None

    async def list_owned(self, owner_id: str) -> list[CredentialRow]:
        """Credentials owned by an actor, oldest first (ULIDs sort by time)."""
        result = await self.db.execute(
            f"SELECT * FROM {TABLE} WHERE owner_id = ? ORDER BY id", [owner_id]
        )
        return [CredentialRow.model_validate(dict(row)) for row in result.rows]

    async def list_by_ids(self, ids: list[str]) -> list[CredentialRow]:
        """Credentials with these ids, oldest first. Unknown ids are skipped."""
        if not ids:
            return []
        # One JSON parameter rather than N placeholders: no variable limit.
        result = await self.db.execute(
            f"SELECT * FROM {TABLE}"
            " WHERE id IN (SELECT value FROM json_each(?)) ORDER BY id",
            [json.dumps(list(ids))],
        )
        return [CredentialRow.model_validate(dict(row)) for row in result.rows]

    async def list_all(self) -> list[CredentialRow]:
        result = await self.db.execute(f"SELECT * FROM {TABLE} ORDER BY id")
        return [CredentialRow.model_validate(dict(row)) for row in result.rows]

    # ----------------------------------------------------------------- writes

    async def insert(
        self,
        *,
        type: str,
        label: str,
        owner_id: str,
        secret_encrypted: bytes,
        created_by: str,
        google_subject: str | None = None,
        google_email: str | None = None,
        scopes: list[str] | None = None,
    ) -> CredentialRow:
        """Insert a new credential with a fresh ULID.

        For ``google_oauth`` use ``upsert_oauth()``: a second row for the same
        (owner, Google account) violates the unique index here.
        """
        validate_type(type)
        id = str(ULID())

        def insert_credential(conn):
            conn.execute(
                f"INSERT INTO {TABLE} (id, type, label, owner_id, google_subject,"
                " google_email, scopes, secret_encrypted, created_by)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                [
                    id,
                    type,
                    label,
                    owner_id,
                    google_subject,
                    google_email,
                    json.dumps(scopes or []),
                    secret_encrypted,
                    created_by,
                ],
            )

        await self.db.execute_write_fn(insert_credential)
        return await self._get_existing(id)

    async def upsert_oauth(
        self,
        owner_id: str,
        subject: str,
        *,
        google_email: str | None,
        label: str,
        scopes: list[str],
        secret_encrypted: bytes,
        actor_id: str,
    ) -> tuple[CredentialRow, bool]:
        """Insert or update the OAuth credential for (owner, Google ``sub``).

        Reconnecting the same Google account updates it in place (D9): new
        secret, scopes and email, status reset to ok. The existing label is
        kept, so a rename survives a reconnect; ``label`` is used only when
        the row is created. Returns ``(row, created)``.
        """
        if not subject:
            # A NULL subject would slip past the unique index (NULLs are
            # distinct), creating duplicates.
            raise ValueError("subject is required")
        new_id = str(ULID())

        def upsert_oauth_credential(conn) -> tuple[str, bool]:
            existing = conn.execute(
                f"SELECT id FROM {TABLE} WHERE type = 'google_oauth'"
                " AND owner_id = ? AND google_subject = ?",
                [owner_id, subject],
            ).fetchone()
            # The conflict target must repeat the partial index's WHERE,
            # or SQLite says it matches no UNIQUE constraint.
            conn.execute(
                f"INSERT INTO {TABLE} (id, type, label, owner_id, google_subject,"
                " google_email, scopes, secret_encrypted, created_by)"
                " VALUES (?, 'google_oauth', ?, ?, ?, ?, ?, ?, ?)"
                " ON CONFLICT (owner_id, google_subject) WHERE type = 'google_oauth'"
                " DO UPDATE SET"
                "   google_email = excluded.google_email,"
                "   scopes = excluded.scopes,"
                "   secret_encrypted = excluded.secret_encrypted,"
                "   status = 'ok',"
                "   status_detail = NULL,"
                f"  updated_at = {NOW},"
                "   updated_by = excluded.created_by",
                [
                    new_id,
                    label,
                    owner_id,
                    subject,
                    google_email,
                    json.dumps(scopes),
                    secret_encrypted,
                    actor_id,
                ],
            )
            if existing:
                return existing[0], False
            return new_id, True

        id, created = await self.db.execute_write_fn(upsert_oauth_credential)
        return await self._get_existing(id), created

    async def update_secret(
        self,
        id: str,
        secret_encrypted: bytes,
        *,
        actor_id: str,
        expected_secret: bytes | None = None,
    ) -> bool:
        """Replace the stored secret (key rotation) and clear a broken status.

        Bumps ``updated_at``, which the token cache uses to spot rotation.
        With ``expected_secret``, a compare-and-swap: applies only if the row
        still holds exactly that blob, so a concurrent reconnect or rotation
        is never overwritten. Returns False if nothing was updated.
        """

        def update_credential_secret(conn) -> bool:
            sql = (
                f"UPDATE {TABLE} SET secret_encrypted = ?, status = 'ok',"
                f" status_detail = NULL, updated_at = {NOW}, updated_by = ?"
                " WHERE id = ?"
            )
            params: list = [secret_encrypted, actor_id, id]
            if expected_secret is not None:
                sql += " AND secret_encrypted = ?"
                params.append(expected_secret)
            return conn.execute(sql, params).rowcount > 0

        return await self.db.execute_write_fn(update_credential_secret)

    async def reencrypt_secret(self, id: str, *, old: bytes, new: bytes) -> bool:
        """Swap in the same secret re-encrypted under a newer key.

        Unlike ``update_secret`` this is not an edit: status, ``updated_*``
        and the token cache are untouched. Only applies if the row still
        holds ``old``, so a concurrent real update is never overwritten.
        """

        def reencrypt_credential_secret(conn) -> bool:
            cursor = conn.execute(
                f"UPDATE {TABLE} SET secret_encrypted = ?"
                " WHERE id = ? AND secret_encrypted = ?",
                [new, id, old],
            )
            return cursor.rowcount > 0

        return await self.db.execute_write_fn(reencrypt_credential_secret)

    async def rename(self, id: str, label: str, *, actor_id: str) -> bool:
        def rename_credential(conn) -> bool:
            cursor = conn.execute(
                f"UPDATE {TABLE} SET label = ?, updated_at = {NOW}, updated_by = ?"
                " WHERE id = ?",
                [label, actor_id, id],
            )
            return cursor.rowcount > 0

        return await self.db.execute_write_fn(rename_credential)

    async def mark_broken(
        self, id: str, detail: str, *, expected_secret: bytes | None = None
    ) -> bool:
        """Flag a credential as unusable (e.g. ``invalid_grant``).

        ``detail`` is shown to users: never put a token or key in it. With
        ``expected_secret``, applies only if the row still holds exactly that
        blob: a secret Google rejected must not break a row a reconnect has
        since replaced. Returns False if nothing was updated.
        """

        def mark_credential_broken(conn) -> bool:
            sql = (
                f"UPDATE {TABLE} SET status = 'broken', status_detail = ? WHERE id = ?"
            )
            params: list = [detail, id]
            if expected_secret is not None:
                sql += " AND secret_encrypted = ?"
                params.append(expected_secret)
            return conn.execute(sql, params).rowcount > 0

        return await self.db.execute_write_fn(mark_credential_broken)

    async def mark_ok(self, id: str) -> bool:
        def mark_credential_ok(conn) -> bool:
            cursor = conn.execute(
                f"UPDATE {TABLE} SET status = 'ok', status_detail = NULL WHERE id = ?",
                [id],
            )
            return cursor.rowcount > 0

        return await self.db.execute_write_fn(mark_credential_ok)

    async def touch_used(self, id: str, actor_id: str) -> bool:
        def touch_credential_used(conn) -> bool:
            cursor = conn.execute(
                f"UPDATE {TABLE} SET last_used_at = {NOW}, last_used_by = ?"
                " WHERE id = ?",
                [actor_id, id],
            )
            return cursor.rowcount > 0

        return await self.db.execute_write_fn(touch_credential_used)

    async def delete(self, id: str) -> bool:
        def delete_credential(conn) -> bool:
            cursor = conn.execute(f"DELETE FROM {TABLE} WHERE id = ?", [id])
            return cursor.rowcount > 0

        return await self.db.execute_write_fn(delete_credential)

    # ---------------------------------------------------------------- helpers

    async def _get_existing(self, id: str) -> CredentialRow:
        row = await self.get(id)
        if row is None:
            raise RuntimeError(f"Credential {id} vanished after write")
        return row
