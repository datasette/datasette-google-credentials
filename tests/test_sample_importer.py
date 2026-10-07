"""The sample importer (samples/google_sheets_import.py), loaded the way
`just dev` loads it (plugins_dir) and run against the mock Sheets API."""

import html
import json
from pathlib import Path

import jwt
import pytest
from cryptography.fernet import Fernet
from datasette.events import CreateTableEvent, InsertRowsEvent
from datasette.plugins import pm
from datasette.utils import module_from_path
from datasette_acl.grants import Principal, grant
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
from datasette_google_credentials.permissions import ADD_SERVICE_ACCOUNT, RESOURCE_TYPE
from datasette_google_credentials.service_account import add_service_account

SAMPLES = Path(__file__).parent.parent / "samples"
SAMPLE = SAMPLES / "google_sheets_import.py"
PAGE = "/-/google-sheets-import/data"
ALICE = {"id": "alice"}  # create-table on data
BOB = {"id": "bob"}  # nothing
CAROL = {"id": "carol"}  # insert-row only
SHEET_URL = "https://docs.google.com/spreadsheets/d/{}/edit"

sample = module_from_path(str(SAMPLE), "google_sheets_import_under_test")


@pytest.fixture
def importer(mock_google):
    """Unregister the sample afterwards: plugins_dir registers it on the
    global plugin manager."""
    yield
    if pm.get_plugin(SAMPLE.name) is not None:
        pm.unregister(name=SAMPLE.name)


async def make_datasette(mock_google):
    datasette = mock_google.datasette(
        plugin_config={"encryption-key": Fernet.generate_key().decode()},
        plugins_dir=str(SAMPLES),
        config={
            "permissions": {ADD_SERVICE_ACCOUNT: {"id": "alice"}},
            "databases": {
                "data": {
                    "permissions": {
                        "create-table": {"id": "alice"},
                        "insert-row": {"id": ["alice", "carol"]},
                    }
                }
            },
        },
    )
    datasette.add_memory_database("importer_test", name="data")
    await datasette.invoke_startup()
    events = []
    real_track_event = datasette.track_event

    async def track_event(event):
        events.append(event)
        await real_track_event(event)

    datasette.track_event = track_event
    datasette._test_events = events
    return datasette


async def add_oauth(
    datasette, mock_google, scopes=(SCOPE_OPENID, SCOPE_EMAIL, SCOPE_SHEETS)
):
    """Alice's OAuth credential for user@example.com (the default connect grant)."""
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
    return await add_service_account(datasette, ALICE, key_json, "Importer SA")


async def post(datasette, actor, **form):
    data = {"url": "", "sheet": "", "table": "", "headers": "1"} | form
    if data["headers"] is None:
        del data["headers"]
    return await datasette.client.post(PAGE, data=data, actor=actor)


async def rows(datasette, table):
    result = await datasette.get_database("data").execute(
        f"select * from [{table}] order by rowid"
    )
    return [dict(row) for row in result.rows]


async def columns(datasette, table):
    return [
        (c.name, c.type)
        for c in await datasette.get_database("data").table_column_details(table)
    ]


def sheets_calls(mock_google):
    return mock_google.calls("/v4/spreadsheets/", host=SHEETS_HOST)


# --- Unit: the local helpers ---------------------------------------------------


def test_sample_uses_only_the_public_api():
    import ast

    import datasette_google_credentials

    tree = ast.parse(SAMPLE.read_text())
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            if node.module.startswith("datasette_google_credentials"):
                assert node.module == "datasette_google_credentials", node.module
                imported |= {alias.name for alias in node.names}
        elif isinstance(node, ast.Import):
            assert not any(
                a.name.startswith("datasette_google_credentials") for a in node.names
            )
    assert imported
    assert imported <= set(datasette_google_credentials.__all__)


@pytest.mark.parametrize(
    "text,expected",
    [
        (
            "https://docs.google.com/spreadsheets/d/abc_DEF-123/edit",
            ("abc_DEF-123", None),
        ),
        ("https://docs.google.com/spreadsheets/d/abc/edit#gid=1001", ("abc", 1001)),
        ("https://docs.google.com/spreadsheets/d/abc/edit?gid=7#gid=7", ("abc", 7)),
        (
            "https://docs.google.com/spreadsheets/d/abc/edit?usp=sharing&gid=3",
            ("abc", 3),
        ),
        ("https://docs.google.com/spreadsheets/u/1/d/abc/htmlview", ("abc", None)),
        (
            "  1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgvE2upms ",
            (
                "1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgvE2upms",
                None,
            ),
        ),
    ],
)
def test_parse_sheet_url(text, expected):
    assert sample.parse_sheet_url(text) == expected


@pytest.mark.parametrize(
    "text",
    [
        "",
        "not a url",
        "https://example.com/spreadsheets/d/abc/edit",
        "https://docs.google.com/document/d/abc",
    ],
)
def test_parse_sheet_url_rejects(text):
    with pytest.raises(ValueError):
        sample.parse_sheet_url(text)


def test_column_names():
    assert sample.column_names([" id ", None, "Name", "name", "", "name_2"], 7) == [
        "id",
        "column_2",
        "Name",
        "name_2",
        "column_5",
        "name_2_2",
        "column_7",
    ]
    assert sample.column_names([], 2) == ["column_1", "column_2"]
    assert sample.column_names([1, 2.5, True], 3) == ["1", "2.5", "True"]


def test_quote_sheet_title():
    assert sample.quote_sheet_title("students") == "'students'"
    assert sample.quote_sheet_title("Bob's A1") == "'Bob''s A1'"


# --- The database action + form --------------------------------------------------


@pytest.mark.asyncio
async def test_database_action_needs_create_table(mock_google, importer):
    datasette = await make_datasette(mock_google)
    response = await datasette.client.get("/data", actor=ALICE)
    assert response.status_code == 200
    assert f'href="{PAGE}"' in response.text
    assert "Import from Google Sheets" in response.text
    for actor in (BOB, CAROL, None):
        response = await datasette.client.get("/data", actor=actor)
        assert "Import from Google Sheets" not in response.text


@pytest.mark.asyncio
async def test_form_lists_credentials(mock_google, service_account_keys, importer):
    datasette = await make_datasette(mock_google)
    oauth = await add_oauth(datasette, mock_google)
    sa = await add_sa(datasette, service_account_keys)
    response = await datasette.client.get(PAGE, actor=ALICE)
    assert response.status_code == 200
    page = html.unescape(response.text)
    # The full `spreadsheets` grant qualifies for spreadsheets.readonly (D27).
    assert f'value="{oauth.id}"' in page
    assert f'value="{sa.id}"' in page
    assert SA_TEST in page
    assert (
        "/-/google-credentials/connect?return_to=%2F-%2Fgoogle-sheets-import%2Fdata"
        in page
    )


@pytest.mark.asyncio
async def test_form_needs_create_table(mock_google, importer):
    datasette = await make_datasette(mock_google)
    for actor in (BOB, CAROL, None):
        response = await datasette.client.get(PAGE, actor=actor)
        assert response.status_code == 403
    assert (
        await datasette.client.get("/-/google-sheets-import/nope", actor=ALICE)
    ).status_code == 404


# --- Imports ------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_import_with_oauth_credential(mock_google, importer):
    datasette = await make_datasette(mock_google)
    cred = await add_oauth(datasette, mock_google)
    response = await post(
        datasette,
        ALICE,
        credential=cred.id,
        url=SHEET_URL.format("students") + "#gid=1001",
        table="assignments",
    )
    assert response.status_code == 302, response.text
    assert response.headers["location"] == "/data/assignments"
    assert await rows(datasette, "assignments") == [
        {"id": 101, "title": "Essay: Modern Poetry", "max_score": 100},
        {"id": 102, "title": "Lab: Chemical Reactions", "max_score": 50.5},
    ]
    # UNFORMATTED_VALUE keeps numbers numeric; that's all the typing there is.
    assert await columns(datasette, "assignments") == [
        ("id", "INTEGER"),
        ("title", "TEXT"),
        ("max_score", "REAL"),
    ]

    # The gid picked the tab via the metadata call, then values for its title.
    meta, values = sheets_calls(mock_google)
    assert meta.path == "/v4/spreadsheets/students"
    assert meta.query["fields"] == ["sheets.properties"]
    assert values.path == "/v4/spreadsheets/students/values/'assignments'"
    assert values.query["valueRenderOption"] == ["UNFORMATTED_VALUE"]

    create, insert = [
        e
        for e in datasette._test_events
        if isinstance(e, CreateTableEvent | InsertRowsEvent)
    ]
    assert isinstance(create, CreateTableEvent)
    assert (create.database, create.table, create.actor) == (
        "data",
        "assignments",
        ALICE,
    )
    assert "CREATE TABLE" in create.schema
    assert isinstance(insert, InsertRowsEvent)
    assert (insert.table, insert.num_rows, insert.ignore, insert.replace) == (
        "assignments",
        2,
        False,
        False,
    )


@pytest.mark.asyncio
async def test_import_with_service_account(mock_google, service_account_keys, importer):
    datasette = await make_datasette(mock_google)
    sa = await add_sa(datasette, service_account_keys)
    response = await post(
        datasette,
        ALICE,
        credential=sa.id,
        url=SHEET_URL.format("students"),
        table="students",
    )
    assert response.status_code == 302, response.text
    # No gid: the first tab.
    imported = await rows(datasette, "students")
    assert len(imported) == 5
    assert imported[0] == {
        "id": 1,
        "name": "Alice Chen",
        "grade_level": 10,
        "email": "alice@school.edu",
    }
    # The SA minted only the narrow scope the importer asked for.
    # (Last token POST: add_service_account's live test mints one too.)
    token_post = mock_google.calls("/token", method="POST")[-1]
    assert token_post.form is not None
    claims = jwt.decode(
        token_post.form["assertion"], options={"verify_signature": False}
    )
    assert claims["scope"] == SCOPE_SHEETS_RO


@pytest.mark.asyncio
async def test_sheet_by_name(mock_google, importer):
    datasette = await make_datasette(mock_google)
    cred = await add_oauth(datasette, mock_google)
    response = await post(
        datasette,
        ALICE,
        credential=cred.id,
        # An explicit sheet name wins over the URL's gid (case-insensitive).
        url=SHEET_URL.format("students") + "#gid=0",
        sheet="Assignments",
        table="a",
    )
    assert response.status_code == 302, response.text
    assert len(await rows(datasette, "a")) == 2


@pytest.mark.asyncio
async def test_ragged_rows_and_duplicate_headers(mock_google, importer):
    datasette = await make_datasette(mock_google)
    cred = await add_oauth(datasette, mock_google)
    response = await post(
        datasette,
        ALICE,
        credential=cred.id,
        url=SHEET_URL.format("ragged"),
        table="ragged",
    )
    assert response.status_code == 302, response.text
    assert [name for name, _ in await columns(datasette, "ragged")] == [
        "name",
        "column_2",
        "name_2",
        "score",
        "column_5",
    ]
    # Short rows padded with NULL, the blank middle row dropped.
    assert await rows(datasette, "ragged") == [
        {
            "name": "alice",
            "column_2": "x",
            "name_2": "a2",
            "score": 10,
            "column_5": None,
        },
        {
            "name": "bob",
            "column_2": None,
            "name_2": None,
            "score": None,
            "column_5": None,
        },
        {
            "name": "carol",
            "column_2": None,
            "name_2": None,
            "score": 30,
            "column_5": "extra",
        },
    ]


@pytest.mark.asyncio
async def test_without_header_row(mock_google, importer):
    datasette = await make_datasette(mock_google)
    cred = await add_oauth(datasette, mock_google)
    response = await post(
        datasette,
        ALICE,
        credential=cred.id,
        url=SHEET_URL.format("students"),
        table="raw",
        headers=None,
    )
    assert response.status_code == 302, response.text
    imported = await rows(datasette, "raw")
    assert len(imported) == 6
    assert imported[0] == {
        "column_1": "id",
        "column_2": "name",
        "column_3": "grade_level",
        "column_4": "email",
    }


@pytest.mark.asyncio
async def test_existing_table_appends_with_insert_row(mock_google, importer):
    datasette = await make_datasette(mock_google)
    cred = await add_oauth(datasette, mock_google)
    db = datasette.get_database("data")
    await db.execute_write(
        "create table Students (id integer, name text, grade_level integer, email text)"
    )
    response = await post(
        datasette,
        ALICE,
        credential=cred.id,
        url=SHEET_URL.format("students"),
        table="students",  # matches case-insensitively
    )
    assert response.status_code == 302, response.text
    assert response.headers["location"] == "/data/Students"
    assert len(await rows(datasette, "Students")) == 5
    assert not [e for e in datasette._test_events if isinstance(e, CreateTableEvent)]

    # Extra columns would need alter-table: refused, nothing written.
    response = await post(
        datasette,
        ALICE,
        credential=cred.id,
        url=SHEET_URL.format("students") + "#gid=1001",
        table="Students",
    )
    assert response.status_code == 400
    assert "has no column(s) title, max_score" in html.unescape(response.text)
    assert len(await rows(datasette, "Students")) == 5


# --- Permissions + CSRF -------------------------------------------------------------


@pytest.mark.asyncio
async def test_no_create_table_permission(mock_google, importer):
    datasette = await make_datasette(mock_google)
    # carol can insert-row but not create-table.
    response = await post(
        datasette, CAROL, credential="x", url=SHEET_URL.format("students"), table="new"
    )
    assert response.status_code == 403
    assert "You can&#39;t create tables in" in response.text
    assert sheets_calls(mock_google) == []
    assert not await datasette.get_database("data").table_exists("new")


@pytest.mark.asyncio
async def test_existing_table_needs_insert_row(mock_google, importer):
    datasette = await make_datasette(mock_google)
    await datasette.get_database("data").execute_write("create table t (id integer)")
    response = await post(
        datasette, BOB, credential="x", url=SHEET_URL.format("students"), table="t"
    )
    assert response.status_code == 403
    assert "insert rows into" in response.text
    assert sheets_calls(mock_google) == []


@pytest.mark.asyncio
async def test_cross_site_post_is_rejected(mock_google, importer):
    datasette = await make_datasette(mock_google)
    cred = await add_oauth(datasette, mock_google)
    response = await datasette.client.post(
        PAGE,
        data={"credential": cred.id, "url": SHEET_URL.format("students"), "table": "x"},
        actor=ALICE,
        headers={"Sec-Fetch-Site": "cross-site", "Origin": "https://evil.example"},
    )
    assert response.status_code == 403
    assert sheets_calls(mock_google) == []


# --- Errors ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_service_account_share_with_email_hint(
    mock_google, service_account_keys, importer
):
    datasette = await make_datasette(mock_google)
    sa = await add_sa(datasette, service_account_keys)
    response = await post(
        datasette, ALICE, credential=sa.id, url=SHEET_URL.format("private"), table="p"
    )
    assert response.status_code == 403
    assert (
        f"Share this sheet with <strong><code>{SA_TEST}</code></strong>"
        in response.text
    )
    assert "Reconnect Google" not in response.text
    assert "Bearer" not in response.text
    assert "PRIVATE KEY" not in response.text
    # The form keeps what was typed.
    assert 'value="p"' in response.text
    assert not await datasette.get_database("data").table_exists("p")


@pytest.mark.asyncio
async def test_service_account_shared_with_someone_else(
    mock_google, service_account_keys, importer
):
    # Carol uses alice's SA through an acl grant; the hint names the SA.
    datasette = await make_datasette(mock_google)
    sa = await add_sa(datasette, service_account_keys)
    await grant(
        datasette,
        RESOURCE_TYPE,
        sa.id,
        principal=Principal.actor("carol"),
        role="User",
        by_actor="alice",
    )
    await datasette.get_database("data").execute_write("create table t (secret text)")
    response = await post(
        datasette, CAROL, credential=sa.id, url=SHEET_URL.format("private"), table="t"
    )
    assert response.status_code == 403
    assert f"<code>{SA_TEST}</code>" in response.text


@pytest.mark.asyncio
async def test_oauth_unshared_sheet_has_no_share_hint(mock_google, importer):
    datasette = await make_datasette(mock_google)
    cred = await add_oauth(datasette, mock_google)
    response = await post(
        datasette, ALICE, credential=cred.id, url=SHEET_URL.format("private"), table="p"
    )
    assert response.status_code == 403
    assert f"The Google account {DEFAULT_USER.email} can&#39;t open" in response.text
    assert "Share this sheet with" not in response.text


@pytest.mark.asyncio
async def test_missing_scopes_shows_reconnect_link(mock_google, importer):
    datasette = await make_datasette(mock_google)
    cred = await add_oauth(datasette, mock_google, scopes=(SCOPE_OPENID, SCOPE_EMAIL))
    response = await post(
        datasette,
        ALICE,
        credential=cred.id,
        url=SHEET_URL.format("students"),
        table="s",
    )
    assert response.status_code == 403
    assert "missing required scopes" in response.text
    assert (
        '<a href="/-/google-credentials/connect?return_to=%2F-%2Fgoogle-sheets-import%2Fdata">'
        "Reconnect Google</a>"
    ) in response.text
    assert sheets_calls(mock_google) == []


@pytest.mark.asyncio
async def test_broken_credential_shows_reconnect_link(mock_google, importer):
    datasette = await make_datasette(mock_google)
    cred = await add_oauth(datasette, mock_google)
    await InternalDB(datasette.get_internal_database()).mark_broken(
        cred.id, "Token has been expired or revoked."
    )
    response = await post(
        datasette,
        ALICE,
        credential=cred.id,
        url=SHEET_URL.format("students"),
        table="s",
    )
    assert response.status_code == 409
    assert "expired or revoked" in response.text
    assert "Reconnect Google</a>" in response.text


@pytest.mark.asyncio
async def test_someone_elses_credential_is_not_found(mock_google, importer):
    datasette = await make_datasette(mock_google)
    cred = await add_oauth(datasette, mock_google)
    await datasette.get_database("data").execute_write("create table t (id integer)")
    response = await post(
        datasette,
        CAROL,
        credential=cred.id,
        url=SHEET_URL.format("students"),
        table="t",
    )
    assert response.status_code == 404
    assert "Credential not found" in response.text
    assert sheets_calls(mock_google) == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "form,message",
    [
        (
            {"url": "https://example.com/x", "table": "t"},
            "look like a Google Sheets URL",
        ),
        ({"url": SHEET_URL.format("students"), "table": " "}, "Enter a table name"),
        (
            {"url": SHEET_URL.format("students") + "#gid=99", "table": "t"},
            "No sheet with gid 99",
        ),
        (
            {"url": SHEET_URL.format("students"), "sheet": "nope", "table": "t"},
            "No sheet called",
        ),
    ],
)
async def test_bad_input(mock_google, importer, form, message):
    datasette = await make_datasette(mock_google)
    cred = await add_oauth(datasette, mock_google)
    response = await post(datasette, ALICE, credential=cred.id, **form)
    assert response.status_code == 400
    assert message in html.unescape(response.text)


@pytest.mark.asyncio
async def test_sheets_server_error(mock_google, importer):
    datasette = await make_datasette(mock_google)
    cred = await add_oauth(datasette, mock_google)
    mock_google.faults.fail("/v4/spreadsheets/students", 500)
    response = await post(
        datasette,
        ALICE,
        credential=cred.id,
        url=SHEET_URL.format("students"),
        table="t",
    )
    assert response.status_code == 502
    assert "Google Sheets returned an error" in response.text
