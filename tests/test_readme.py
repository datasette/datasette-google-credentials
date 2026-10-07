"""The README's "A complete consumer" example, extracted verbatim and loaded
as a plugins_dir plugin against the mock Google, so the documented code keeps
working.

The block is the first ```python fence after the
``<!-- readme-consumer-example -->`` marker in README.md.
"""

import json
import re
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import jwt
import pytest
from cryptography.fernet import Fernet
from datasette.plugins import pm
from mock_google import SHEETS_HOST
from mock_google.keys import SA_TEST
from mock_google.oauth import (
    DEFAULT_USER,
    SCOPE_EMAIL,
    SCOPE_OPENID,
    SCOPE_SHEETS,
    SCOPE_SHEETS_RO,
)

from datasette_google_credentials.crypto import encrypt_secret
from datasette_google_credentials.internal_db import InternalDB
from datasette_google_credentials.permissions import ADD_SERVICE_ACCOUNT
from datasette_google_credentials.service_account import add_service_account

README = Path(__file__).parent.parent / "README.md"
MARKER = "<!-- readme-consumer-example -->"
PLUGIN_FILE = "readme_sheet_preview.py"
PAGE = "/-/sheet-preview"
ALICE = {"id": "alice"}
BOB = {"id": "bob"}


def consumer_example() -> str:
    text = README.read_text()
    assert text.count(MARKER) == 1, f"README needs exactly one {MARKER}"
    match = re.search(r"```python\n(.*?)\n```", text[text.index(MARKER) :], re.S)
    assert match, f"no ```python block after {MARKER}"
    return match.group(1) + "\n"


@pytest.fixture
def preview(mock_google, tmp_path):
    """Datasette with the README example in its plugins_dir. Unregistered
    afterwards: plugins_dir registers it on the global plugin manager."""
    (tmp_path / PLUGIN_FILE).write_text(consumer_example())
    yield tmp_path
    if pm.get_plugin(PLUGIN_FILE) is not None:
        pm.unregister(name=PLUGIN_FILE)


async def make_datasette(mock_google, plugins_dir):
    datasette = mock_google.datasette(
        plugin_config={"encryption-key": Fernet.generate_key().decode()},
        plugins_dir=str(plugins_dir),
        config={"permissions": {ADD_SERVICE_ACCOUNT: {"id": "alice"}}},
    )
    await datasette.invoke_startup()
    return datasette


async def add_oauth(
    datasette, mock_google, scopes=(SCOPE_OPENID, SCOPE_EMAIL, SCOPE_SHEETS)
):
    """Alice's OAuth connection for user@example.com."""
    refresh_token = mock_google.oauth.issue_refresh_token(
        DEFAULT_USER, frozenset(scopes)
    )
    row, _ = await InternalDB(datasette.get_internal_database()).upsert_oauth(
        "alice",
        DEFAULT_USER.sub,
        google_email=DEFAULT_USER.email,
        label=DEFAULT_USER.email,
        scopes=list(scopes),
        secret_encrypted=encrypt_secret(datasette, {"refresh_token": refresh_token}),
        actor_id="alice",
    )
    return row


async def add_sa(datasette, service_account_keys):
    """The sa-test@ service account, added by alice (its Manager)."""
    key_json = json.dumps(service_account_keys["test"].key_json())
    return await add_service_account(datasette, ALICE, key_json, "Preview SA")


def test_readme_has_the_example():
    code = consumer_example()
    assert "def register_routes" in code
    assert PAGE in code


@pytest.mark.asyncio
async def test_lists_credentials(mock_google, service_account_keys, preview):
    datasette = await make_datasette(mock_google, preview)
    oauth = await add_oauth(datasette, mock_google)
    sa = await add_sa(datasette, service_account_keys)
    response = await datasette.client.get(PAGE, actor=ALICE)
    assert response.status_code == 200
    data = response.json()
    # Own OAuth connections first, then shared service accounts.
    assert [c["id"] for c in data["credentials"]] == [oauth.id, sa.id]
    assert data["credentials"][1]["google_email"] == SA_TEST
    assert (
        data["connect_url"]
        == "/-/google-credentials/connect?return_to=%2F-%2Fsheet-preview"
    )
    # Nothing secret in the listing.
    assert "private_key" not in response.text
    assert "refresh_token" not in response.text


@pytest.mark.asyncio
async def test_reads_with_oauth(mock_google, preview):
    datasette = await make_datasette(mock_google, preview)
    oauth = await add_oauth(datasette, mock_google)
    response = await datasette.client.get(
        f"{PAGE}?credential={oauth.id}&spreadsheet=students", actor=ALICE
    )
    assert response.status_code == 200, response.text
    values = response.json()["values"]
    assert response.json()["ok"] is True
    assert values[0] == ["id", "name", "grade_level", "email"]
    assert len(values) == 5  # A1:E5
    (call,) = mock_google.calls("/v4/spreadsheets/", host=SHEETS_HOST)
    assert call.path == "/v4/spreadsheets/students/values/A1:E5"


@pytest.mark.asyncio
async def test_reads_with_service_account(mock_google, service_account_keys, preview):
    datasette = await make_datasette(mock_google, preview)
    sa = await add_sa(datasette, service_account_keys)
    response = await datasette.client.get(
        f"{PAGE}?credential={sa.id}&spreadsheet=students", actor=ALICE
    )
    assert response.status_code == 200, response.text
    # The example uses Google's default FORMATTED_VALUE: everything is a string.
    assert response.json()["values"][1] == ["1", "Alice Chen", "10", "alice@school.edu"]
    # The service account was minted exactly the scope the example asks for.
    # (Last token POST: add_service_account's live test mints one too.)
    token_post = mock_google.calls("/token", method="POST")[-1]
    assert token_post.form is not None
    claims = jwt.decode(
        token_post.form["assertion"], options={"verify_signature": False}
    )
    assert claims["scope"] == SCOPE_SHEETS_RO


@pytest.mark.asyncio
async def test_unshared_sheet_gives_share_hint(
    mock_google, service_account_keys, preview
):
    datasette = await make_datasette(mock_google, preview)
    sa = await add_sa(datasette, service_account_keys)
    response = await datasette.client.get(
        f"{PAGE}?credential={sa.id}&spreadsheet=private", actor=ALICE
    )
    assert response.status_code == 502
    body = response.json()
    assert body["ok"] is False
    assert body["share_with"] == SA_TEST


@pytest.mark.asyncio
async def test_other_actors_credential_is_404(mock_google, preview):
    datasette = await make_datasette(mock_google, preview)
    oauth = await add_oauth(datasette, mock_google)
    response = await datasette.client.get(
        f"{PAGE}?credential={oauth.id}&spreadsheet=students", actor=BOB
    )
    assert response.status_code == 404
    assert response.json()["code"] == "not_found"
    # Bob's list doesn't include it either.
    listing = await datasette.client.get(PAGE, actor=BOB)
    assert listing.json()["credentials"] == []
    assert not mock_google.calls("/v4/spreadsheets/", host=SHEETS_HOST)


@pytest.mark.asyncio
async def test_missing_scopes_redirects_to_connect(mock_google, preview):
    datasette = await make_datasette(mock_google, preview)
    oauth = await add_oauth(datasette, mock_google, scopes=(SCOPE_OPENID, SCOPE_EMAIL))
    here = f"{PAGE}?credential={oauth.id}&spreadsheet=students"
    response = await datasette.client.get(here, actor=ALICE)
    assert response.status_code == 302
    location = urlsplit(response.headers["location"])
    assert location.path == "/-/google-credentials/connect"
    assert parse_qs(location.query) == {"return_to": [here]}
    assert not mock_google.calls("/v4/spreadsheets/", host=SHEETS_HOST)
