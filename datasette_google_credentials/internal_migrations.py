"""Internal-database schema for datasette-google-credentials (via sqlite-migrate).

Append-only: never edit an applied migration, add a new ``m00N_...`` one.
(One-time exception: the pre-release rename from datasette-google-auth edited
m001's table/index names and the migration set name in place, since no
deployed database existed. Delete any old dev internal DB.)

One table, ``datasette_google_credentials`` (D10): service-account keys
and per-user OAuth connections, secrets Fernet-encrypted in
``secret_encrypted``.

``type`` has no CHECK constraint, so future credential types (api_key,
config/ADC, domain-wide delegation) don't need a table rebuild. It is
validated in Python instead (``internal_db.CredentialType``).
"""

from sqlite_migrate import Migrations
from sqlite_utils import Database

internal_migrations = Migrations("datasette-google-credentials.internal")


@internal_migrations()
def m001_credentials(db: Database):
    db.executescript("""
        CREATE TABLE IF NOT EXISTS datasette_google_credentials (
            id               TEXT PRIMARY KEY,  -- ULID
            type             TEXT NOT NULL,     -- validated in Python
            label            TEXT NOT NULL,
            owner_id         TEXT NOT NULL,
            google_subject   TEXT,
            google_email     TEXT,
            scopes           TEXT NOT NULL DEFAULT '[]',  -- JSON list, granted
            secret_encrypted BLOB NOT NULL,     -- Fernet token
            status           TEXT NOT NULL DEFAULT 'ok'
                                  CHECK (status IN ('ok','broken')),
            status_detail    TEXT,
            last_used_at     TEXT,
            last_used_by     TEXT,
            created_at       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            created_by       TEXT NOT NULL,
            updated_at       TEXT,
            updated_by       TEXT
        );
        -- One OAuth credential per (owner, Google account); reconnecting the
        -- same account updates in place (D9).
        CREATE UNIQUE INDEX IF NOT EXISTS datasette_google_credentials_oauth_unique
            ON datasette_google_credentials(owner_id, google_subject)
            WHERE type = 'google_oauth';
        CREATE INDEX IF NOT EXISTS datasette_google_credentials_owner
            ON datasette_google_credentials(owner_id);
    """)
