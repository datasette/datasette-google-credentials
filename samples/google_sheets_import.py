"""
Sample plugin: import a Google Sheet into a table, one-shot, started by a user.

Proves the datasette-google-credentials broker API with a real consumer (D2, D14).
It uses only the public API (``from datasette_google_credentials import ...``); there
is no Sheets helper (D12), so it calls the Sheets REST API with
``cred.request()``.

Install: copy this file into your plugins directory

Usage:
    datasette tmp.db --plugins-dir=samples/      (or `just dev`)

Then pick "Import from Google Sheets" from a database's actions menu, which
links to ``/-/google-sheets-import/<database>``.

Behaviour:

* The credential picker lists what ``list_credentials()`` returns for
  ``spreadsheets.readonly``, the narrowest scope an import needs. A default
  Connect Google grant (``spreadsheets``) qualifies through the broker's
  scope-implication table (D27).
* A new table needs ``create-table`` on the database. Importing into an
  existing table appends rows and needs ``insert-row`` on it; the sheet may
  not bring columns the table lacks (that would need ``alter-table``).
* Cells come back as ``UNFORMATTED_VALUE`` (numbers stay numbers, dates as
  formatted strings); empty cells become NULL. There is no other type
  inference. Header names are trimmed, blank ones become ``column_N`` and
  duplicates get ``_2``, ``_3``...; short rows are padded, blank rows skipped.
* A 403/404 from Sheets on a service account says which address to share the
  sheet with: the key UX this sample exists to prove.
"""

from __future__ import annotations

import re
import sqlite3
from typing import Any
from urllib.parse import quote, urlsplit

from datasette import Forbidden, NotFound, Response, hookimpl
from datasette.events import CreateTableEvent, InsertRowsEvent
from datasette.resources import DatabaseResource, TableResource
from datasette.utils import tilde_decode, tilde_encode
from sqlite_utils import Database
from sqlite_utils.utils import suggest_column_types

from datasette_google_credentials import (
    CredentialBroken,
    GoogleCredentialsError,
    MissingScopes,
    connect_url,
    error_response,
    get_credential,
    list_credentials,
)

SHEETS_READONLY = "https://www.googleapis.com/auth/spreadsheets.readonly"
SHEETS_API = "https://sheets.googleapis.com/v4/spreadsheets"
PATH = "/-/google-sheets-import/"


# --- Parsing (the evidence for a future Sheets helper, D12) --------------------

# /spreadsheets/d/ID/edit, or /spreadsheets/u/1/d/ID/... when signed in to
# several Google accounts.
_SPREADSHEET_ID = re.compile(r"/spreadsheets/(?:u/\d+/)?d/([A-Za-z0-9_-]+)")
_BARE_ID = re.compile(r"[A-Za-z0-9_-]{10,}")
_GID = re.compile(r"(?:^|[&#?])gid=(\d+)")


def parse_sheet_url(text: str) -> tuple[str, int | None]:
    """``(spreadsheet_id, gid)`` from a Sheets URL or a bare spreadsheet id.

    The gid comes from ``#gid=N`` (what the browser shows) or ``?gid=N``.
    Raises ``ValueError`` if no spreadsheet id can be found.
    """
    text = text.strip()
    if _BARE_ID.fullmatch(text):
        return text, None
    parts = urlsplit(text)
    match = _SPREADSHEET_ID.search(parts.path)
    if parts.hostname != "docs.google.com" or not match:
        raise ValueError("That doesn't look like a Google Sheets URL")
    gid = _GID.search("#" + parts.fragment) or _GID.search("?" + parts.query)
    return match.group(1), int(gid.group(1)) if gid else None


def quote_sheet_title(title: str) -> str:
    """A1 notation for a whole sheet: always quoted, so a title like ``A1``
    can't be read as a cell reference."""
    return "'" + title.replace("'", "''") + "'"


def column_names(header: list[Any], width: int) -> list[str]:
    """``width`` unique column names from a header row: trimmed, blanks become
    ``column_N`` (1-based position), duplicates (case-insensitive, as SQLite
    compares them) get ``_2``, ``_3``..."""
    names: list[str] = []
    seen: set[str] = set()
    for i in range(width):
        raw = header[i] if i < len(header) else None
        name = "" if raw is None else str(raw).strip()
        name = name or f"column_{i + 1}"
        candidate, n = name, 2
        while candidate.casefold() in seen:
            candidate, n = f"{name}_{n}", n + 1
        seen.add(candidate.casefold())
        names.append(candidate)
    return names


def to_records(
    rows: list[list[Any]], *, first_row_is_header: bool
) -> tuple[list[str], list[dict[str, Any]]]:
    """``(columns, records)`` from Sheets ``values``: empty cells -> None,
    short rows padded, blank rows dropped."""
    cells = [[None if value == "" else value for value in row] for row in rows]
    header: list[Any] = []
    if first_row_is_header and cells:
        header, cells = cells[0], cells[1:]
    width = max((len(row) for row in [header, *cells]), default=0)
    columns = column_names(header, width)
    records = [
        dict(zip(columns, row + [None] * (width - len(row)), strict=True))
        for row in cells
        if any(value is not None for value in row)
    ]
    return columns, records


# --- Talking to Sheets ----------------------------------------------------------


class ImportFailed(Exception):
    """A user-facing import error. Messages never carry tokens or keys."""

    def __init__(
        self,
        message: str,
        *,
        status: int = 400,
        reconnect_url: str | None = None,
        share_with: str | None = None,
    ):
        super().__init__(message)
        self.message = message
        self.status = status
        self.reconnect_url = reconnect_url
        self.share_with = share_with


def _google_message(response) -> str:
    try:
        message = response.json()["error"]["message"]
    except (ValueError, KeyError, TypeError):
        message = None
    return message or f"HTTP {response.status_code}"


def _sheets_failure(response, cred) -> ImportFailed:
    info = cred.info
    if response.status_code in (403, 404):
        if info.type == "service_account":
            # Google can't tell "missing" from "not shared with you" apart for
            # us, and the fix for the likely case is the same: share it.
            return ImportFailed(
                "This service account can't open that spreadsheet. Check the URL, "
                "and share the sheet with the service account's email address.",
                status=403,
                share_with=info.google_email,
            )
        return ImportFailed(
            f"The Google account {info.google_email or info.label} can't open that "
            "spreadsheet. Check the URL, or ask its owner to share it with you.",
            status=403,
        )
    return ImportFailed(
        f"Google Sheets returned an error: {_google_message(response)}", status=502
    )


async def sheet_title(cred, spreadsheet_id: str, gid: int | None, sheet: str) -> str:
    """The title of the tab to import: ``sheet`` by name, else the URL's gid,
    else the first tab."""
    response = await cred.request(
        "GET",
        f"{SHEETS_API}/{quote(spreadsheet_id, safe='')}",
        params={"fields": "sheets.properties"},
    )
    if response.status_code != 200:
        raise _sheets_failure(response, cred)
    tabs = sorted(
        (s["properties"] for s in response.json().get("sheets", [])),
        key=lambda p: p.get("index", 0),
    )
    if not tabs:
        raise ImportFailed("That spreadsheet has no sheets")
    if sheet:
        for props in tabs:
            if props["title"].casefold() == sheet.casefold():
                return props["title"]
        raise ImportFailed(f"No sheet called {sheet!r} in that spreadsheet")
    if gid is not None:
        for props in tabs:
            if props.get("sheetId") == gid:
                return props["title"]
        raise ImportFailed(f"No sheet with gid {gid} in that spreadsheet")
    return tabs[0]["title"]


async def sheet_values(cred, spreadsheet_id: str, title: str) -> list[list[Any]]:
    response = await cred.request(
        "GET",
        f"{SHEETS_API}/{quote(spreadsheet_id, safe='')}/values/"
        + quote(quote_sheet_title(title), safe=""),
        params={
            "valueRenderOption": "UNFORMATTED_VALUE",
            # Otherwise dates arrive as spreadsheet serial numbers.
            "dateTimeRenderOption": "FORMATTED_STRING",
        },
    )
    if response.status_code != 200:
        raise _sheets_failure(response, cred)
    return response.json().get("values", [])


# --- Writing the table ------------------------------------------------------------


def _existing_table(conn, name: str) -> str | None:
    """The stored name of table ``name`` (SQLite names are case-insensitive)."""
    row = conn.execute(
        "select name from sqlite_master where type = 'table' "
        "and name = ? collate nocase",
        [name],
    ).fetchone()
    return row[0] if row else None


def table_writer(
    database: str,
    table: str,
    expect_existing: str | None,
    columns: list[str],
    records: list[dict[str, Any]],
    actor: dict[str, Any] | None,
):
    """The ``execute_write_fn`` callback: create ``table`` (or append to
    ``expect_existing``) and insert ``records``. It returns
    ``(stored table name, created)``.

    A closure, not a dataclass: plugins-dir files aren't in ``sys.modules``,
    which ``@dataclass`` needs.
    """

    def import_sheet_rows(conn, track_event) -> tuple[str, bool]:
        # Runs on the write connection inside one transaction; Datasette sends
        # the tracked events only after it commits.
        if _existing_table(conn, table) != expect_existing:
            raise ImportFailed(
                f"Table {table!r} was created or dropped meanwhile — try again",
                status=409,
            )
        db = Database(conn)
        if expect_existing:
            target = db.table(expect_existing)
            have = {column.name.casefold() for column in target.columns}
            extra = [c for c in columns if c.casefold() not in have]
            if extra:
                raise ImportFailed(
                    f"Table {expect_existing!r} has no column(s) "
                    + ", ".join(extra)
                    + ". Import into a new table instead."
                )
        else:
            target = db.table(table)
            types = suggest_column_types(records) if records else {}
            target.create({c: types.get(c, str) for c in columns})
            track_event(
                CreateTableEvent(
                    actor=actor,
                    database=database,
                    table=target.name,
                    schema=target.schema,
                )
            )
        target.insert_all(records)
        track_event(
            InsertRowsEvent(
                actor=actor,
                database=database,
                table=target.name,
                num_rows=len(records),
                ignore=False,
                replace=False,
            )
        )
        return target.name, not expect_existing

    return import_sheet_rows


# --- The page -----------------------------------------------------------------------

TEMPLATE = """
{% extends "base.html" %}
{% block title %}Import from Google Sheets{% endblock %}
{% block content %}
<h1>Import a Google Sheet into {{ database }}</h1>

{% if error %}
<div class="message-error">
  <p>{{ error }}</p>
  {% if share_with %}
  <p>Share this sheet with <strong><code>{{ share_with }}</code></strong>
    (Viewer is enough), then try again.</p>
  {% endif %}
  {% if reconnect_url %}
  <p><a href="{{ reconnect_url }}">Reconnect Google</a> to fix this.</p>
  {% endif %}
</div>
{% endif %}

<form class="core" method="post" action="{{ action }}">
  <p>
    <label for="credential">Google account</label>
    {% if credentials %}
    <select id="credential" name="credential">
      {% for c in credentials %}
      <option value="{{ c.id }}"{% if c.id == form.credential %} selected{% endif %}>
        {{ c.label }}{% if c.google_email and c.google_email != c.label %} ({{ c.google_email }}){% endif %}
        — {{ "service account" if c.type == "service_account" else "your Google account" }}
        {%- if c.status != "ok" %} [{{ c.status }}]{% endif %}
      </option>
      {% endfor %}
    </select>
    {% else %}
    <em>No Google credentials yet.</em>
    {% endif %}
    <a href="{{ connect }}">Connect Google</a>
  </p>
  <p>
    <label for="url">Spreadsheet URL</label>
    <input type="text" id="url" name="url" size="80" required value="{{ form.url }}"
      placeholder="https://docs.google.com/spreadsheets/d/.../edit#gid=0">
  </p>
  <p>
    <label for="sheet">Sheet (optional)</label>
    <input type="text" id="sheet" name="sheet" value="{{ form.sheet }}"
      placeholder="defaults to the tab in the URL, or the first tab">
  </p>
  <p>
    <label for="table">Table name</label>
    <input type="text" id="table" name="table" required value="{{ form.table }}">
  </p>
  <p>
    <label><input type="checkbox" name="headers" value="1"
      {%- if form.headers %} checked{% endif %}> First row is headers</label>
  </p>
  <p><input type="submit" value="Import"></p>
</form>
<p>A new table needs create-table permission. An existing table gets the rows
appended (insert-row permission) and must already have every column.</p>
{% endblock %}
"""


def _path(datasette, database: str) -> str:
    return datasette.urls.path(PATH + tilde_encode(database))


async def _render(
    datasette,
    request,
    database: str,
    form: dict[str, Any],
    *,
    status: int = 200,
    failure: ImportFailed | None = None,
) -> Response:
    here = _path(datasette, database)
    credentials = await list_credentials(
        datasette, actor=request.actor, scopes=[SHEETS_READONLY]
    )
    template = datasette.get_jinja_environment(request).from_string(TEMPLATE)
    html = await datasette.render_template(
        template,
        {
            "database": database,
            "action": here,
            "connect": connect_url(datasette, return_to=here),
            "credentials": credentials,
            "form": form,
            "error": failure.message if failure else None,
            "share_with": failure.share_with if failure else None,
            "reconnect_url": failure.reconnect_url if failure else None,
        },
        request=request,
    )
    return Response.html(html, status=status)


def _from_auth_error(
    datasette, database: str, error: GoogleCredentialsError
) -> ImportFailed:
    """Show any broker error; offer a reconnect that comes back here when
    reconnecting can fix it."""
    reconnect = None
    if isinstance(error, MissingScopes | CredentialBroken) and error.reconnect_url:
        reconnect = connect_url(datasette, return_to=_path(datasette, database))
    # error_response() is the broker's own status mapping (404, 403, 409, ...).
    return ImportFailed(
        str(error), status=error_response(error).status, reconnect_url=reconnect
    )


async def _import(datasette, request, database: str, form: dict[str, Any]) -> str:
    """Run the import; return the table name. Raises ``ImportFailed``."""
    db = datasette.get_database(database)
    actor = request.actor
    table = form["table"].strip()
    if not table:
        raise ImportFailed("Enter a table name")
    if not form["credential"]:
        raise ImportFailed("Choose a Google account")
    try:
        spreadsheet_id, gid = parse_sheet_url(form["url"])
    except ValueError as error:
        raise ImportFailed(str(error)) from None

    # 1. Permission: create-table for a new table, insert-row for an existing one.
    existing = await db.execute_fn(lambda conn: _existing_table(conn, table))
    if existing:
        allowed = await datasette.allowed(
            action="insert-row",
            resource=TableResource(database, existing),
            actor=actor,
        )
        if not allowed:
            raise ImportFailed(f"You can't insert rows into {existing!r}", status=403)
    elif not await datasette.allowed(
        action="create-table", resource=DatabaseResource(database), actor=actor
    ):
        raise ImportFailed(f"You can't create tables in {database!r}", status=403)

    # 2-5. Credential, then the sheet's values.
    try:
        cred = await get_credential(
            datasette, form["credential"], actor=actor, scopes=[SHEETS_READONLY]
        )
        title = await sheet_title(cred, spreadsheet_id, gid, form["sheet"].strip())
        rows = await sheet_values(cred, spreadsheet_id, title)
    except GoogleCredentialsError as error:
        raise _from_auth_error(datasette, database, error) from None
    if not rows:
        raise ImportFailed(f"Sheet {title!r} is empty")
    columns, records = to_records(rows, first_row_is_header=form["headers"])

    # 6-7. One write transaction; core events fire after it commits.
    write = table_writer(database, table, existing, columns, records, actor)
    try:
        name, created = await db.execute_write_fn(write)
    except sqlite3.Error as error:
        raise ImportFailed(f"Could not write {table!r}: {error}") from None
    verb = "Created" if created else "Appended to"
    datasette.add_message(
        request,
        f"{verb} {name} with {len(records)} rows from sheet {title!r}",
        datasette.INFO,
    )
    return name


async def import_page(datasette, request):
    database = tilde_decode(request.url_vars["database"])
    try:
        db = datasette.get_database(database)
    except KeyError:
        raise NotFound(f"Database not found: {database}") from None
    if not db.is_mutable:
        raise Forbidden(f"Database {database!r} is immutable")

    if request.method != "POST":
        # Offer the form to anyone who could create a table here; an import
        # into an existing table is checked (insert-row) on submit.
        if not await datasette.allowed(
            action="create-table",
            resource=DatabaseResource(database),
            actor=request.actor,
        ):
            raise Forbidden("You can't create tables in this database")
        return await _render(
            datasette,
            request,
            database,
            {"credential": "", "url": "", "sheet": "", "table": "", "headers": True},
        )

    post = await request.post_vars()
    form = {
        "credential": post.get("credential", ""),
        "url": post.get("url", ""),
        "sheet": post.get("sheet", ""),
        "table": post.get("table", ""),
        "headers": bool(post.get("headers")),
    }
    try:
        table = await _import(datasette, request, database, form)
    except ImportFailed as failure:
        return await _render(
            datasette, request, database, form, status=failure.status, failure=failure
        )
    return Response.redirect(datasette.urls.table(database, table))


# --- Hooks ------------------------------------------------------------------------


@hookimpl
def register_routes():
    return [(r"^/-/google-sheets-import/(?P<database>[^/]+)$", import_page)]


@hookimpl
def database_actions(datasette, actor, database, request):
    async def inner():
        db = datasette.databases.get(database)
        if db is None or not db.is_mutable:
            return []
        if not await datasette.allowed(
            action="create-table", resource=DatabaseResource(database), actor=actor
        ):
            return []
        return [
            {
                "href": _path(datasette, database),
                "label": "Import from Google Sheets",
                "description": "Create a table from a Google Sheet",
            }
        ]

    return inner
