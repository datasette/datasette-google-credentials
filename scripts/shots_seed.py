"""Dev-only seed plugin for the doc-screenshot harness (NOT shipped).

``frontend/scripts/screenshots.mjs`` copies this file into a throwaway
``--plugins-dir`` (``scripts/`` itself holds other scripts that mustn't load
as plugins) and boots Datasette with it. It does three things:

1. ``actor_from_request``: the actor is the ``x-shots-actor`` request header's
   value, so Playwright can browse as ``alice`` without any cookie signing.
2. ``actors_from_ids``: display names for the admin page's owner column.
3. ``startup``: when ``plugins.shots_seed.seed`` is true, inserts demo
   credentials **directly into the internal DB** (there is no way to add
   one over HTTP without Google accepting it) plus datasette-acl grants.

Nothing here can reach Google: the secrets are fake bytes, not Fernet tokens,
and the pages being shot only list credentials, which never decrypts. The
harness also points every Google URL at a closed local port.

Determinism: fixed ULIDs (so the list order is fixed), fixed timestamps,
``@example.com`` / ``demo-project`` emails.
"""

import json
from typing import Any

from datasette import hookimpl
from datasette_acl import startup as acl_startup
from datasette_acl.grants import Principal, grant

from datasette_google_auth import startup as google_auth_startup
from datasette_google_auth.broker import SA_BROKEN_DETAIL
from datasette_google_auth.internal_db import TABLE
from datasette_google_auth.oauth import BROKEN_DETAIL
from datasette_google_auth.permissions import RESOURCE_TYPE, seed_manager

HEADER = "x-shots-actor"

NAMES = {
    "alice": "Alice Chen",
    "bob": "Bob Diaz",
    "carol": "Carol Evans",
}

SHEETS = "https://www.googleapis.com/auth/spreadsheets"
# What Google grants for the default `openid email …/spreadsheets` request.
GRANTED = ["openid", "https://www.googleapis.com/auth/userinfo.email", SHEETS]
SA_DOMAIN = "demo-project.iam.gserviceaccount.com"

# Not a Fernet token: anything that tried to decrypt it would fail loudly.
FAKE_SECRET = b"shots-demo: not an encrypted secret"

# ULIDs built from each created_at (ms) with a counter for the random part,
# so id order is creation order, as every list shows them.
CREDENTIALS: list[dict[str, Any]] = [
    {
        "id": "01M1E406H00000000000000001",
        "type": "google_oauth",
        "label": "alice@example.com",
        "owner_id": "alice",
        "google_subject": "100000000000000000001",
        "google_email": "alice@example.com",
        "scopes": GRANTED,
        "last_used_at": "2026-09-28T16:42:00.000Z",
        "created_at": "2026-09-01T09:15:00.000Z",
    },
    {
        "id": "01M1GTP8200000000000000002",
        "type": "google_oauth",
        "label": "alice.research@example.com",
        "owner_id": "alice",
        "google_subject": "100000000000000000002",
        "google_email": "alice.research@example.com",
        "scopes": GRANTED,
        "status": "broken",
        "status_detail": BROKEN_DETAIL,
        "last_used_at": "2026-08-14T11:05:00.000Z",
        "created_at": "2026-09-02T10:30:00.000Z",
    },
    {
        "id": "01M1KS3FR00000000000000003",
        "type": "service_account",
        "label": "Reports bot",
        "owner_id": "alice",
        "google_subject": "100000000000000000101",
        "google_email": f"reports-bot@{SA_DOMAIN}",
        "last_used_at": "2026-09-29T08:00:00.000Z",
        "created_at": "2026-09-03T14:00:00.000Z",
    },
    {
        "id": "01M1NSFDQ00000000000000004",
        "type": "service_account",
        "label": "Warehouse importer",
        "owner_id": "bob",
        "google_subject": "100000000000000000102",
        "google_email": f"warehouse-import@{SA_DOMAIN}",
        "last_used_at": "2026-09-27T22:30:00.000Z",
        "created_at": "2026-09-04T08:45:00.000Z",
    },
    {
        "id": "01M1RQ16G00000000000000005",
        "type": "google_oauth",
        "label": "bob@example.com",
        "owner_id": "bob",
        "google_subject": "100000000000000000003",
        "google_email": "bob@example.com",
        "scopes": GRANTED,
        "last_used_at": "2026-09-25T13:20:00.000Z",
        "created_at": "2026-09-05T12:00:00.000Z",
    },
    {
        "id": "01M1VQQNY00000000000000006",
        "type": "service_account",
        "label": "Finance export",
        "owner_id": "carol",
        "google_subject": "100000000000000000103",
        "google_email": f"finance-export@{SA_DOMAIN}",
        "status": "broken",
        "status_detail": SA_BROKEN_DETAIL,
        "last_used_at": "2026-09-10T07:00:00.000Z",
        "created_at": "2026-09-06T16:10:00.000Z",
    },
]

# (credential id, actor id, role) on top of each owner's Manager grant.
SHARES = [
    ("01M1KS3FR00000000000000003", "bob", "Editor"),
    ("01M1KS3FR00000000000000003", "carol", "User"),
    # The "shared with you as User" case on alice's page.
    ("01M1NSFDQ00000000000000004", "alice", "User"),
]


@hookimpl
def actor_from_request(request):
    actor_id = request.headers.get(HEADER)
    return {"id": actor_id} if actor_id else None


@hookimpl
def actors_from_ids(actor_ids):
    return {
        actor_id: {"id": actor_id, "name": NAMES[actor_id]}
        if actor_id in NAMES
        else {"id": actor_id}
        for actor_id in actor_ids
    }


@hookimpl
def startup(datasette):
    async def inner():
        if not (datasette.plugin_config("shots_seed") or {}).get("seed"):
            return
        # Startup hooks run in no guaranteed order: run datasette-acl's and
        # google-auth's first (both idempotent) so their tables exist and
        # acl knows every action before the grants below.
        await acl_startup(datasette)()
        await google_auth_startup(datasette)()
        await seed(datasette)

    return inner


async def seed(datasette):
    db = datasette.get_internal_database()

    def insert_credentials(conn):
        for c in CREDENTIALS:
            conn.execute(
                f"INSERT OR REPLACE INTO {TABLE} (id, type, label, owner_id,"
                " google_subject, google_email, scopes, secret_encrypted, status,"
                " status_detail, last_used_at, last_used_by, created_at,"
                " created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                [
                    c["id"],
                    c["type"],
                    c["label"],
                    c["owner_id"],
                    c["google_subject"],
                    c["google_email"],
                    json.dumps(c.get("scopes", [])),
                    FAKE_SECRET,
                    c.get("status", "ok"),
                    c.get("status_detail"),
                    c["last_used_at"],
                    c["owner_id"],
                    c["created_at"],
                    c["owner_id"],
                ],
            )

    await db.execute_write_fn(insert_credentials)
    for c in CREDENTIALS:
        if c["type"] == "service_account":
            await seed_manager(datasette, c["id"], c["owner_id"])
    owners = {c["id"]: c["owner_id"] for c in CREDENTIALS}
    for credential_id, actor_id, role in SHARES:
        await grant(
            datasette,
            RESOURCE_TYPE,
            credential_id,
            principal=Principal.actor(actor_id),
            role=role,
            by_actor=owners[credential_id],
        )
