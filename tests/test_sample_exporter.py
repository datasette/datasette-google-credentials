"""The sample exporter (samples/google_sheets_export.py), loaded the way
`just dev` loads it (plugins_dir) and run against the mock Sheets API."""

import html
import json
from pathlib import Path
from urllib.parse import urlencode

import pytest
from cryptography.fernet import Fernet
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
from mock_google.sheets import WHOLE

from datasette_google_credentials.crypto import encrypt_secret
from datasette_google_credentials.internal_db import InternalDB
from datasette_google_credentials.permissions import ADD_SERVICE_ACCOUNT, RESOURCE_TYPE
from datasette_google_credentials.service_account import add_service_account

SAMPLES = Path(__file__).parent.parent / "samples"
SAMPLE = SAMPLES / "google_sheets_export.py"
PAGE = "/-/google-sheets-export"
ALICE = {"id": "alice"}  # execute-sql on data, view-table on secret
BOB = {"id": "bob"}  # neither
SHEET_URL = "https://docs.google.com/spreadsheets/d/{}/edit"

sample = module_from_path(str(SAMPLE), "google_sheets_export_under_test")


@pytest.fixture
def exporter(mock_google):
    """Unregister the sample afterwards: plugins_dir registers it on the
    global plugin manager."""
    yield
    if pm.get_plugin(SAMPLE.name) is not None:
        pm.unregister(name=SAMPLE.name)


def loaded():
    """The module plugins_dir registered (what the routes actually use)."""
    return pm.get_plugin(SAMPLE.name)


async def make_datasette(mock_google, settings=None):
    datasette = mock_google.datasette(
        plugin_config={"encryption-key": Fernet.generate_key().decode()},
        plugins_dir=str(SAMPLES),
        settings=settings or {},
        config={
            "permissions": {ADD_SERVICE_ACCOUNT: {"id": "alice"}},
            "databases": {
                "data": {
                    "permissions": {"execute-sql": {"id": "alice"}},
                    "tables": {
                        "secret": {"permissions": {"view-table": {"id": "alice"}}}
                    },
                }
            },
        },
    )
    db = datasette.add_memory_database("exporter_test", name="data")
    await datasette.invoke_startup()
    await db.execute_write_script(
        """
        create table people (id integer primary key, name text, score real, note text);
        insert into people values (1, 'Ann', 9.5, null);
        insert into people values (2, 'Bo', 7, '=HYPERLINK("http://evil.example","x")');
        insert into people values (3, 'Cy', null, '+1');
        create table secret (id integer primary key, value text);
        insert into secret values (1, 'classified');
        """
    )
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
    return await add_service_account(datasette, ALICE, key_json, "Exporter SA")


async def post(datasette, actor, **form):
    data = {"database": "data", "target": "new", "mode": "replace", "headers": "1"}
    data |= form
    data = {k: v for k, v in data.items() if v is not None}
    return await datasette.client.post(PAGE, data=data, actor=actor)


def sheets_calls(mock_google, path="/v4/spreadsheets"):
    return mock_google.calls(path, host=SHEETS_HOST)


def appends(mock_google):
    return [c for c in sheets_calls(mock_google) if c.path.endswith(":append")]


def created(mock_google):
    """The one spreadsheet the export created: (spreadsheet, first tab)."""
    (ss,) = [s for s in mock_google.sheets.spreadsheets.values() if s.created_by]
    return ss, ss.sheets[0]


def contents(sheet):
    return sheet.read(WHOLE)[1]


PEOPLE = [
    ["id", "name", "score", "note"],
    [1, "Ann", 9.5],  # values.get trims trailing empty cells
    [2, "Bo", 7, '=HYPERLINK("http://evil.example","x")'],
    [3, "Cy", "", "+1"],
]


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


def test_parse_sheet_url_and_quote():
    assert sample.parse_sheet_url(SHEET_URL.format("abc") + "#gid=7") == ("abc", 7)
    assert sample.parse_sheet_url(" 1BxiMVs0XRA5nFMdKvBd ") == (
        "1BxiMVs0XRA5nFMdKvBd",
        None,
    )
    with pytest.raises(ValueError):
        sample.parse_sheet_url("https://example.com/spreadsheets/d/abc/edit")
    assert sample.quote_sheet_title("Bob's A1") == "'Bob''s A1'"


def test_cell_value():
    assert sample.cell_value(None) == ""
    assert sample.cell_value("=1+1") == "=1+1"
    assert sample.cell_value(3) == 3
    assert sample.cell_value(2.5) == 2.5
    assert sample.cell_value(True) is True
    assert (
        sample.cell_value({"$base64": True, "encoded": "AAE="})
        == '{"$base64": true, "encoded": "AAE="}'
    )


def test_chunk_rows():
    rows = [[i] for i in range(5)]
    assert sample.chunk_rows(rows, 2) == [[[0], [1]], [[2], [3]], [[4]]]
    assert sample.chunk_rows([], 2) == []
    # A chunk may not end on a blank row: append would find the table's end
    # above it and put the next chunk on top of it.
    blank = ["", ""]
    rows = [["a", 1], blank, blank, ["b", 2], blank]
    assert sample.chunk_rows(rows, 2) == [
        [["a", 1], blank, blank, ["b", 2]],
        [blank],
    ]


# --- Actions + form --------------------------------------------------------------


@pytest.mark.asyncio
async def test_table_and_query_actions(mock_google, exporter):
    datasette = await make_datasette(mock_google)
    response = await datasette.client.get("/data/people", actor=ALICE)
    href = PAGE + "?" + urlencode({"database": "data", "table": "people"})
    assert html.escape(href) in response.text
    assert "Export to Google Sheets" in response.text

    sql = "select * from people where id > :min"
    response = await datasette.client.get(
        "/data/-/query?" + urlencode({"sql": sql, "min": "1"}), actor=ALICE
    )
    href = (
        PAGE
        + "?"
        + urlencode(
            {"database": "data", "sql": sql, "params": json.dumps({"min": "1"})}
        )
    )
    assert html.escape(href) in response.text

    # Anonymous: no credentials possible, no action.
    response = await datasette.client.get("/data/people")
    assert "Export to Google Sheets" not in response.text


@pytest.mark.asyncio
async def test_form_lists_spreadsheets_credentials(
    mock_google, service_account_keys, exporter
):
    datasette = await make_datasette(mock_google)
    oauth = await add_oauth(datasette, mock_google)
    readonly = await add_oauth(
        datasette,
        mock_google,
        scopes=(SCOPE_OPENID, SCOPE_EMAIL, SCOPE_SHEETS_RO),
    )
    assert readonly.id == oauth.id  # same Google account: updated in place
    sa = await add_sa(datasette, service_account_keys)
    response = await datasette.client.get(
        PAGE + "?database=data&table=people", actor=ALICE
    )
    assert response.status_code == 200
    page = html.unescape(response.text)
    # Read-only grant doesn't qualify for writing; the SA mints what it needs.
    assert f'value="{oauth.id}"' not in page
    assert f'value="{sa.id}"' in page
    assert "share it with the service account's email address as" in page
    assert (
        "/-/google-credentials/connect?return_to="
        "%2F-%2Fgoogle-sheets-export%3Fdatabase%3Ddata%26table%3Dpeople"
    ) in page


@pytest.mark.asyncio
async def test_form_access(mock_google, exporter):
    datasette = await make_datasette(mock_google)
    get = datasette.client.get
    assert (await get(PAGE + "?database=data&table=people")).status_code == 403
    assert (
        await get(PAGE + "?database=data&table=secret", actor=BOB)
    ).status_code == 403
    assert (
        await get(PAGE + "?database=data&sql=select+1", actor=BOB)
    ).status_code == 403
    assert (await get(PAGE + "?database=nope&table=t", actor=ALICE)).status_code == 404
    assert (await get(PAGE + "?database=data", actor=ALICE)).status_code == 404


# --- Exports ------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_export_table_to_new_sheet_with_oauth(mock_google, exporter):
    datasette = await make_datasette(mock_google)
    cred = await add_oauth(datasette, mock_google)
    response = await post(datasette, ALICE, credential=cred.id, table="people")
    assert response.status_code == 200, response.text
    ss, sheet = created(mock_google)
    assert ss.title == "people"
    assert ss.created_by == DEFAULT_USER.email
    # Formula-looking text is stored literally (RAW); numbers stay numbers.
    assert contents(sheet) == PEOPLE
    link = f"https://docs.google.com/spreadsheets/d/{ss.spreadsheet_id}/edit#gid=0"
    assert f'<a href="{link}">' in response.text
    assert "Exported 3 rows" in response.text

    create = sheets_calls(mock_google)[0]
    assert (create.method, create.path) == ("POST", "/v4/spreadsheets")
    assert create.json == {"properties": {"title": "people"}}
    (append,) = appends(mock_google)
    assert append.path == f"/v4/spreadsheets/{ss.spreadsheet_id}/values/'Sheet1':append"
    assert append.query["valueInputOption"] == ["RAW"]
    assert append.query["insertDataOption"] == ["INSERT_ROWS"]
    assert append.json["values"][2][3] == '=HYPERLINK("http://evil.example","x")'


@pytest.mark.asyncio
async def test_export_query_to_new_sheet_with_oauth(mock_google, exporter):
    datasette = await make_datasette(mock_google)
    cred = await add_oauth(datasette, mock_google)
    response = await post(
        datasette,
        ALICE,
        credential=cred.id,
        sql="select name, note, id * 2 as twice from people where id >= :min",
        params=json.dumps({"min": "2"}),
        title="My export",
        headers=None,
    )
    assert response.status_code == 200, response.text
    ss, sheet = created(mock_google)
    assert ss.title == "My export"
    assert contents(sheet) == [
        ["Bo", '=HYPERLINK("http://evil.example","x")', 4],
        ["Cy", "+1", 6],
    ]
    assert all(c.query["valueInputOption"] == ["RAW"] for c in appends(mock_google))


@pytest.mark.asyncio
async def test_export_to_existing_sheet_with_service_account(
    mock_google, service_account_keys, exporter
):
    datasette = await make_datasette(mock_google)
    sa = await add_sa(datasette, service_account_keys)
    response = await post(
        datasette,
        ALICE,
        credential=sa.id,
        table="people",
        target="existing",
        url=SHEET_URL.format("students") + "#gid=1001",
    )
    assert response.status_code == 200, response.text
    students = mock_google.sheets.get("students")
    # Replace: the gid's tab is cleared, then written; the other tab untouched.
    assert contents(students.find_sheet("assignments")) == PEOPLE
    assert len(contents(students.find_sheet("students"))) == 6
    assert "#gid=1001" in response.text
    paths = [(c.method, c.path) for c in sheets_calls(mock_google)]
    assert paths == [
        ("GET", "/v4/spreadsheets/students"),
        ("POST", "/v4/spreadsheets/students/values/'assignments':clear"),
        ("POST", "/v4/spreadsheets/students/values/'assignments':append"),
    ]
    assert not [s for s in mock_google.sheets.spreadsheets.values() if s.created_by]

    # Append mode, by tab name, no header: below what's there.
    response = await post(
        datasette,
        ALICE,
        credential=sa.id,
        sql="select id, name from people where id = 1",
        target="existing",
        url=SHEET_URL.format("students"),
        sheet="Students",
        mode="append",
        headers=None,
    )
    assert response.status_code == 200, response.text
    rows = contents(students.find_sheet("students"))
    assert len(rows) == 7
    assert rows[-1] == [1, "Ann"]


@pytest.mark.asyncio
async def test_chunked_writes(mock_google, exporter, monkeypatch):
    datasette = await make_datasette(mock_google, settings={"max_returned_rows": 3})
    db = datasette.get_database("data")
    await db.execute_write_script(
        "create table many (n integer);"
        + "".join(f"insert into many values ({i});" for i in range(10))
    )
    cred = await add_oauth(datasette, mock_google)
    monkeypatch.setattr(loaded(), "CHUNK_ROWS", 4)
    response = await post(datasette, ALICE, credential=cred.id, table="many")
    assert response.status_code == 200, response.text
    # 10 rows paged from Datasette 3 at a time, header + 10 written 4 at a time.
    _, sheet = created(mock_google)
    # Like Datasette's own JSON/CSV exports, a rowid table includes rowid.
    assert contents(sheet) == [["rowid", "n"]] + [[i + 1, i] for i in range(10)]
    assert [len(c.json["values"]) for c in appends(mock_google)] == [4, 4, 3]


@pytest.mark.asyncio
async def test_row_cap(mock_google, exporter, monkeypatch):
    datasette = await make_datasette(mock_google)
    cred = await add_oauth(datasette, mock_google)
    monkeypatch.setattr(loaded(), "MAX_ROWS", 2)
    for source in ({"table": "people"}, {"sql": "select * from people"}):
        response = await post(datasette, ALICE, credential=cred.id, **source)
        assert response.status_code == 413
        assert "more than 2 rows" in response.text
    assert sheets_calls(mock_google) == []


@pytest.mark.asyncio
async def test_cell_cap(mock_google, exporter, monkeypatch):
    datasette = await make_datasette(mock_google)
    cred = await add_oauth(datasette, mock_google)
    monkeypatch.setattr(loaded(), "MAX_CELLS", 15)  # 4 rows x 4 columns = 16
    response = await post(datasette, ALICE, credential=cred.id, table="people")
    assert response.status_code == 413
    assert "16 cells" in response.text
    assert sheets_calls(mock_google) == []


@pytest.mark.asyncio
async def test_truncated_query_is_refused(mock_google, exporter):
    datasette = await make_datasette(mock_google, settings={"max_returned_rows": 2})
    cred = await add_oauth(datasette, mock_google)
    response = await post(
        datasette, ALICE, credential=cred.id, sql="select * from people"
    )
    assert response.status_code == 400
    assert "max_returned_rows (2)" in response.text
    assert sheets_calls(mock_google) == []


# --- Permissions + CSRF -------------------------------------------------------------


@pytest.mark.asyncio
async def test_actor_without_execute_sql_is_blocked(
    mock_google, service_account_keys, exporter
):
    datasette = await make_datasette(mock_google)
    sa = await add_sa(datasette, service_account_keys)
    # Bob may use the SA, but may not run SQL.
    await grant(
        datasette,
        RESOURCE_TYPE,
        sa.id,
        principal=Principal.actor("bob"),
        role="User",
        by_actor="alice",
    )
    response = await post(
        datasette,
        BOB,
        credential=sa.id,
        sql="select * from secret",
        target="existing",
        url=SHEET_URL.format("students"),
    )
    assert response.status_code == 403
    assert "permission to run SQL" in response.text
    assert "classified" not in response.text

    response = await post(
        datasette,
        BOB,
        credential=sa.id,
        table="secret",
        target="existing",
        url=SHEET_URL.format("students"),
    )
    assert response.status_code == 403
    assert "permission to view" in response.text
    assert sheets_calls(mock_google) == []


@pytest.mark.asyncio
async def test_cross_site_post_is_rejected(mock_google, exporter):
    datasette = await make_datasette(mock_google)
    cred = await add_oauth(datasette, mock_google)
    response = await datasette.client.post(
        PAGE,
        data={"database": "data", "table": "people", "credential": cred.id},
        actor=ALICE,
        headers={"Sec-Fetch-Site": "cross-site", "Origin": "https://evil.example"},
    )
    assert response.status_code == 403
    assert sheets_calls(mock_google) == []


# --- Errors ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_service_account_cannot_create_new_spreadsheet(
    mock_google, service_account_keys, exporter
):
    datasette = await make_datasette(mock_google)
    sa = await add_sa(datasette, service_account_keys)
    response = await post(datasette, ALICE, credential=sa.id, table="people")
    assert response.status_code == 400
    text = html.unescape(response.text)
    assert "Service accounts can't create new spreadsheets" in text
    assert (
        f"<strong><code>{SA_TEST}</code></strong>\n    as <strong>Editor</strong>"
        in (text)
    )
    assert sheets_calls(mock_google) == []


@pytest.mark.asyncio
async def test_service_account_needs_editor(
    mock_google, service_account_keys, exporter
):
    datasette = await make_datasette(mock_google)
    sa = await add_sa(datasette, service_account_keys)
    for sheet in ("readonly", "private"):
        response = await post(
            datasette,
            ALICE,
            credential=sa.id,
            table="people",
            target="existing",
            url=SHEET_URL.format(sheet),
        )
        assert response.status_code == 403
        assert f"<code>{SA_TEST}</code></strong>" in response.text
        assert "as <strong>Editor</strong>" in response.text
        assert "Bearer" not in response.text
        assert "PRIVATE KEY" not in response.text
    # Nothing was written to the read-only sheet.
    assert contents(mock_google.sheets.get("readonly").sheets[0]) == [
        ["k", "v"],
        ["a", 1],
    ]


@pytest.mark.asyncio
async def test_oauth_without_edit_access(mock_google, exporter):
    datasette = await make_datasette(mock_google)
    cred = await add_oauth(datasette, mock_google)
    response = await post(
        datasette,
        ALICE,
        credential=cred.id,
        table="people",
        target="existing",
        url=SHEET_URL.format("readonly"),
    )
    assert response.status_code == 403
    assert f"The Google account {DEFAULT_USER.email} can&#39;t edit" in response.text
    assert "Share this sheet with" not in response.text


@pytest.mark.asyncio
async def test_missing_scopes_shows_reconnect_link(mock_google, exporter):
    datasette = await make_datasette(mock_google)
    cred = await add_oauth(
        datasette, mock_google, scopes=(SCOPE_OPENID, SCOPE_EMAIL, SCOPE_SHEETS_RO)
    )
    response = await post(datasette, ALICE, credential=cred.id, table="people")
    assert response.status_code == 403
    assert "missing required scopes" in response.text
    assert (
        '<a href="/-/google-credentials/connect?return_to='
        '%2F-%2Fgoogle-sheets-export%3Fdatabase%3Ddata%26table%3Dpeople">'
        "Reconnect Google</a>"
    ) in response.text
    assert sheets_calls(mock_google) == []


@pytest.mark.asyncio
async def test_partial_failure_reports_rows_written(mock_google, exporter, monkeypatch):
    datasette = await make_datasette(mock_google)
    cred = await add_oauth(datasette, mock_google)
    monkeypatch.setattr(loaded(), "CHUNK_ROWS", 2)
    response = await post(
        datasette,
        ALICE,
        credential=cred.id,
        table="people",
        target="existing",
        url=SHEET_URL.format("students"),
        sheet="assignments",
    )
    assert response.status_code == 200
    mock_google.state.requests.clear()
    append_path = "/v4/spreadsheets/students/values/'assignments':append"
    # First chunk lands, the second fails.
    real_take = mock_google.faults.take
    seen = []

    def take(method, path):
        if path == append_path:
            seen.append(path)
            if len(seen) == 2:
                return 500
        return real_take(method, path)

    monkeypatch.setattr(mock_google.faults, "take", take)
    response = await post(
        datasette,
        ALICE,
        credential=cred.id,
        table="people",
        target="existing",
        url=SHEET_URL.format("students"),
        sheet="assignments",
    )
    assert response.status_code == 502
    assert "Google Sheets returned an error" in response.text
    assert "2 rows were written before this" in response.text


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "form,message",
    [
        ({"credential": ""}, "Choose a Google account"),
        ({"target": "existing", "url": "https://example.com/x"}, "Google Sheets URL"),
        (
            {"target": "existing", "url": SHEET_URL.format("students") + "#gid=99"},
            "No sheet with gid 99",
        ),
        ({"target": "elsewhere"}, "Choose a new or an existing spreadsheet"),
        (
            {"params": "[1]", "sql": "select 1", "table": None},
            "Invalid query parameters",
        ),
        ({"sql": "select nope", "table": None}, "no such column: nope"),
    ],
)
async def test_bad_input(mock_google, exporter, form, message):
    datasette = await make_datasette(mock_google)
    cred = await add_oauth(datasette, mock_google)
    data = {"credential": cred.id, "table": "people"} | form
    response = await post(datasette, ALICE, **data)
    assert response.status_code == 400
    assert message in html.unescape(response.text)
