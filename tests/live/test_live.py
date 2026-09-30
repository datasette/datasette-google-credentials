"""Service-account paths against real Google, through the public API.

Each test adds the live key with ``add_service_account`` (one real token
exchange), so a run makes about a dozen Google calls in all: well inside the
Sheets API's per-minute quota. Don't loop the suite.

Nothing here asserts on an access token or prints the key: see conftest.py.
"""

from __future__ import annotations

import json
import time
from urllib.parse import quote

import httpx2
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from live_support import (
    ALICE,
    SHEET_ENV,
    SHEETS,
    SHEETS_API,
    SHEETS_READONLY,
    SecretText,
)

from datasette_google_auth import (
    CredentialNotFound,
    InvalidServiceAccountKey,
    get_credential,
)
from datasette_google_auth.http import set_transport
from datasette_google_auth.internal_db import InternalDB
from datasette_google_auth.service import delete
from datasette_google_auth.service_account import add_service_account
from datasette_google_auth.token_cache import get_token_cache

pytestmark = [pytest.mark.live, pytest.mark.asyncio]

SCRATCH_TAB = "datasette-google-auth live"
GOOGLE_HOSTS = {"oauth2.googleapis.com", "sheets.googleapis.com"}


def values_url(sheet_id: str, a1: str, suffix: str = "") -> str:
    return f"{SHEETS_API}/{sheet_id}/values/{quote(a1, safe='')}{suffix}"


def quoted(title: str) -> str:
    """A tab title quoted for A1 notation."""
    return "'" + title.replace("'", "''") + "'"


async def test_add_service_account_does_live_exchange(
    datasette, live_key, live_key_fields
):
    info = await add_service_account(datasette, ALICE, live_key, "")
    assert info.type == "service_account"
    assert info.status == "ok"
    assert info.google_email == live_key_fields["client_email"]
    assert info.label == live_key_fields["client_email"]
    rows = await InternalDB(datasette.get_internal_database()).list_owned("alice")
    assert [row.id for row in rows] == [info.id]


async def test_key_google_rejects_is_not_saved(datasette, live_key):
    # Same identity, a private key Google never issued: the exchange must
    # fail with Google's invalid_grant, mapped to InvalidServiceAccountKey.
    data = json.loads(live_key)
    data["private_key"] = (
        rsa.generate_private_key(public_exponent=65537, key_size=2048)
        .private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        .decode()
    )
    with pytest.raises(InvalidServiceAccountKey) as excinfo:
        await add_service_account(datasette, ALICE, SecretText(json.dumps(data)), "")
    # A bare bool, so a failure can't print the message it found key text in.
    leaked = "PRIVATE KEY" in str(excinfo.value)
    assert not leaked, "the error message contains key material"
    assert await InternalDB(datasette.get_internal_database()).list_owned("alice") == []


async def test_read_values(datasette, credential, sheet_id):
    cred = await get_credential(
        datasette, credential.id, actor=ALICE, scopes=[SHEETS_READONLY]
    )
    meta = await cred.request(
        "GET",
        f"{SHEETS_API}/{sheet_id}",
        params={"fields": "spreadsheetId,properties.title,sheets.properties.title"},
    )
    assert meta.status_code == 200, (
        f"Sheets said {meta.status_code}: is {SHEET_ENV} shared with the key's "
        "client_email?"
    )
    body = meta.json()
    assert body["spreadsheetId"] == sheet_id
    first_tab = body["sheets"][0]["properties"]["title"]

    values = await cred.request(
        "GET",
        values_url(sheet_id, f"{quoted(first_tab)}!A1:C3"),
        params={"valueRenderOption": "UNFORMATTED_VALUE"},
    )
    assert values.status_code == 200
    assert values.json()["range"].endswith("!A1:C3")


async def test_write_and_read_back_in_scratch_tab(datasette, credential, sheet_id):
    # Same calls as samples/google_sheets_export.py's "replace": clear, then
    # values:append with RAW input (D32).
    cred = await get_credential(datasette, credential.id, actor=ALICE, scopes=[SHEETS])
    meta = await cred.request(
        "GET", f"{SHEETS_API}/{sheet_id}", params={"fields": "sheets.properties.title"}
    )
    assert meta.status_code == 200
    titles = [sheet["properties"]["title"] for sheet in meta.json()["sheets"]]
    if SCRATCH_TAB not in titles:
        added = await cred.request(
            "POST",
            f"{SHEETS_API}/{sheet_id}:batchUpdate",
            json={"requests": [{"addSheet": {"properties": {"title": SCRATCH_TAB}}}]},
        )
        assert added.status_code == 200, (
            f"addSheet said {added.status_code}: the key's client_email needs "
            "Editor on the sheet"
        )

    tab = quoted(SCRATCH_TAB)
    cleared = await cred.request("POST", values_url(sheet_id, tab, ":clear"), json={})
    assert cleared.status_code == 200

    run = f"run {time.time_ns()}"
    rows = [["marker", run], ["formula", "=1+1"], ["number", 42]]
    appended = await cred.request(
        "POST",
        values_url(sheet_id, f"{tab}!A1", ":append"),
        params={"valueInputOption": "RAW", "insertDataOption": "INSERT_ROWS"},
        json={"values": rows},
    )
    assert appended.status_code == 200
    assert appended.json()["updates"]["updatedRows"] == 3

    read = await cred.request(
        "GET",
        values_url(sheet_id, f"{tab}!A1:B10"),
        params={"valueRenderOption": "UNFORMATTED_VALUE"},
    )
    assert read.status_code == 200
    # RAW keeps "=1+1" literal text: never a formula.
    assert read.json()["values"] == rows


async def test_delete_credential(datasette, credential, sheet_id, live_key_fields):
    cred = await get_credential(
        datasette, credential.id, actor=ALICE, scopes=[SHEETS_READONLY]
    )
    response = await cred.request(
        "GET", f"{SHEETS_API}/{sheet_id}", params={"fields": "spreadsheetId"}
    )
    assert response.status_code == 200
    assert len(get_token_cache(datasette)) == 1

    result = await delete(datasette, ALICE, credential.id)
    assert result.id == credential.id
    assert result.client_email == live_key_fields["client_email"]
    assert result.private_key_id == live_key_fields["private_key_id"]
    assert len(get_token_cache(datasette)) == 0

    with pytest.raises(CredentialNotFound):
        await get_credential(
            datasette, credential.id, actor=ALICE, scopes=[SHEETS_READONLY]
        )
    # The held Credential re-checks the database on every use (D16).
    with pytest.raises(CredentialNotFound):
        await cred.request("GET", f"{SHEETS_API}/{sheet_id}")


class RecordingTransport(httpx2.AsyncBaseTransport):
    """The real network transport, noting each request's host."""

    def __init__(self) -> None:
        self.inner = httpx2.AsyncHTTPTransport()
        self.hosts: list[str] = []

    async def handle_async_request(self, request: httpx2.Request) -> httpx2.Response:
        self.hosts.append(request.url.host)
        return await self.inner.handle_async_request(request)

    async def aclose(self) -> None:
        await self.inner.aclose()


async def test_bogus_token_uri_still_exchanges_at_google(datasette, live_key, sheet_id):
    # A `.invalid` host can never resolve (RFC 2606). The key's token_uri is
    # ignored (D15), so the exchange still happens at oauth2.googleapis.com.
    data = json.loads(live_key)
    data["token_uri"] = "https://token-uri.invalid/token"
    transport = RecordingTransport()
    set_transport(datasette, transport)
    try:
        info = await add_service_account(
            datasette, ALICE, SecretText(json.dumps(data)), "bogus token_uri"
        )
        cred = await get_credential(
            datasette, info.id, actor=ALICE, scopes=[SHEETS_READONLY]
        )
        response = await cred.request(
            "GET", f"{SHEETS_API}/{sheet_id}", params={"fields": "spreadsheetId"}
        )
        assert response.status_code == 200
        await delete(datasette, ALICE, info.id)
    finally:
        set_transport(datasette, None)
        await transport.aclose()
    assert "token-uri.invalid" not in transport.hosts
    assert set(transport.hosts) == GOOGLE_HOSTS
    assert transport.hosts[0] == "oauth2.googleapis.com"
