"""
Sample plugin: export a table or a query's results to a Google Sheet.

The second proving consumer for the datasette-google-auth broker API (D2, D14).
It uses only the public API (``from datasette_google_auth import ...``); there
is no Sheets helper (D12), so it calls the Sheets REST API with
``cred.request()``.

Install: copy this file into your plugins directory

Usage:
    datasette tmp.db --plugins-dir=samples/      (or `just dev`)

Then pick "Export to Google Sheets" from a table's or a SQL query's actions
menu, which links to ``/-/google-sheets-export?database=..&table=..`` (or
``&sql=..``).

Behaviour:

* Rows are read **as the actor** through ``datasette.client`` with
  ``actor=request.actor``, so core enforces every permission (view-table,
  execute-sql, ...) exactly as it would for the actor's own JSON request.
  Columns are what that JSON has (a rowid table includes ``rowid``, as in
  Datasette's CSV export). Tables are paged with ``_next``; a query returns at most Datasette's
  ``max_returned_rows``, and a truncated result is refused rather than
  exported partially.
* Caps: ``MAX_ROWS`` rows and ``MAX_CELLS`` cells (Google allows 20 million
  cells per spreadsheet, shared by every tab). Over a cap nothing is written.
* Values are written with ``valueInputOption=RAW``: Google stores them as
  given, so a value such as ``=IMPORTXML(...)`` or ``+1`` stays literal text
  and is never evaluated as a formula (no formula injection). NULL becomes an
  empty cell; blobs and JSON-ish values become their JSON text.
* Every write is a ``values:append`` of at most ``CHUNK_ROWS`` rows, because
  ``values.update`` can't start outside the sheet's current grid (1,000 rows
  on a new tab) while append grows it. "Replace" clears the tab first.
* Targets: a **new spreadsheet** (OAuth credentials only; it lands in the
  user's Drive), or an **existing spreadsheet** by URL, optionally a tab.
  Service accounts can't create spreadsheets (D28): a file they create lives
  in the service account's own Drive, invisible to the user, and sharing it
  back would need a Drive scope. They export into sheets already shared with
  them as Editor, and a 403/404 says which address to share with.
* A failure part-way through leaves the rows written so far; the error says
  how many.
"""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import quote, urlencode, urlsplit

from datasette import Forbidden, NotFound, Response, hookimpl
from datasette.resources import DatabaseResource, TableResource

from datasette_google_auth import (
    CredentialBroken,
    GoogleAuthError,
    MissingScopes,
    connect_url,
    error_response,
    get_credential,
    list_credentials,
)

SPREADSHEETS = "https://www.googleapis.com/auth/spreadsheets"
SHEETS_API = "https://sheets.googleapis.com/v4/spreadsheets"
PATH = "/-/google-sheets-export"

MAX_ROWS = 50_000
MAX_CELLS = 5_000_000  # a quarter of Google's 20M, leaving room for other tabs
CHUNK_ROWS = 5_000


# --- Parsing (copied from the importer: samples don't import each other) -------

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


class ExportFailed(Exception):
    """A user-facing export error. Messages never carry tokens or keys."""

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


# --- Shaping the values -----------------------------------------------------------


def cell_value(value: Any) -> Any:
    """A Datasette JSON value as a Sheets cell. Written with RAW, so strings
    are never parsed as formulas, numbers or dates."""
    if value is None:
        return ""
    if isinstance(value, bool | int | float | str):
        return value
    # Blobs arrive as {"$base64": true, "encoded": ...}; keep them readable.
    return json.dumps(value)


def chunk_rows(rows: list[list[Any]], size: int) -> list[list[list[Any]]]:
    """Split ``rows`` into appends of about ``size`` rows.

    A chunk never ends on a blank row (unless it's the last): ``values:append``
    finds the end of the existing table by its last non-empty row, so the next
    chunk would land on top of (or before) trailing blank rows.
    """
    chunks: list[list[list[Any]]] = []
    start = 0
    while start < len(rows):
        end = min(start + size, len(rows))
        while end < len(rows) and not any(v != "" for v in rows[end - 1]):
            end += 1
        chunks.append(rows[start:end])
        start = end
    return chunks


def check_caps(columns: list[str], rows: list[list[Any]], *, header: bool) -> None:
    if len(rows) > MAX_ROWS:
        raise ExportFailed(
            f"That's more than {MAX_ROWS:,} rows, the most this exporter writes. "
            "Filter it down with a query first.",
            status=413,
        )
    cells = (len(rows) + header) * len(columns)
    if cells > MAX_CELLS:
        raise ExportFailed(
            f"That's {cells:,} cells, more than the {MAX_CELLS:,} this exporter "
            "writes. Select fewer rows or columns.",
            status=413,
        )


# --- Reading rows as the actor ------------------------------------------------------


def _read_failure(response, what: str) -> ExportFailed:
    if response.status_code == 403:
        return ExportFailed(f"You don't have permission to {what}", status=403)
    if response.status_code == 404:
        return ExportFailed("Table not found", status=404)
    try:
        message = response.json()["error"]
    except (ValueError, KeyError, TypeError):
        message = None
    return ExportFailed(
        message or f"Could not read the rows (HTTP {response.status_code})"
    )


async def read_rows(
    datasette,
    actor: dict[str, Any] | None,
    database: str,
    *,
    table: str | None = None,
    sql: str | None = None,
    params: dict[str, str] | None = None,
) -> tuple[list[str], list[list[Any]]]:
    """``(columns, rows)`` for a table or a query, fetched through
    ``datasette.client`` as ``actor`` so core applies its permission checks.

    Stops reading once past ``MAX_ROWS`` (the caller refuses the export).
    """
    shape = {"_shape": "arrays", "_extra": "columns"}
    if sql is not None:
        named = {
            k: v
            for k, v in (params or {}).items()
            if k != "sql" and not k.startswith("_")
        }
        response = await datasette.client.get(
            datasette.urls.database(database) + "/-/query.json",
            params={"sql": sql, **named, **shape},
            actor=actor,
        )
        if response.status_code != 200:
            raise _read_failure(response, f"run SQL against {database!r}")
        data = response.json()
        if data.get("truncated"):
            raise ExportFailed(
                "That query returned more rows than Datasette's max_returned_rows "
                f"({datasette.setting('max_returned_rows'):,}), so the export "
                "would be incomplete. Export the table, or narrow the query."
            )
        return data["columns"], data["rows"]

    assert table is not None
    path = datasette.urls.table(database, table, format="json")
    columns: list[str] = []
    rows: list[list[Any]] = []
    next_token = None
    while True:
        page_params = {**shape, "_size": "max"}
        if next_token is not None:
            page_params["_next"] = next_token
        response = await datasette.client.get(path, params=page_params, actor=actor)
        if response.status_code != 200:
            raise _read_failure(response, f"view {table!r}")
        data = response.json()
        columns = data["columns"]
        rows.extend(data["rows"])
        next_token = data.get("next")
        if next_token is None or len(rows) > MAX_ROWS:
            return columns, rows


# --- Talking to Sheets ----------------------------------------------------------------


def _google_message(response) -> str:
    try:
        message = response.json()["error"]["message"]
    except (ValueError, KeyError, TypeError):
        message = None
    return message or f"HTTP {response.status_code}"


def _sheets_failure(response, cred, written: int = 0) -> ExportFailed:
    info = cred.info
    partial = f" {written:,} rows were written before this." if written else ""
    if response.status_code in (403, 404):
        if info.type == "service_account":
            # Google can't tell "missing" from "not shared with you" apart for
            # us, and the fix for the likely case is the same: share it.
            return ExportFailed(
                "This service account can't edit that spreadsheet. Check the URL, "
                "and share the sheet with the service account's email address "
                "as an Editor." + partial,
                status=403,
                share_with=info.google_email,
            )
        return ExportFailed(
            f"The Google account {info.google_email or info.label} can't edit that "
            "spreadsheet. Check the URL, or ask its owner to make you an Editor."
            + partial,
            status=403,
        )
    return ExportFailed(
        f"Google Sheets returned an error: {_google_message(response)}.{partial}",
        status=502,
    )


def _spreadsheet_url(spreadsheet_id: str, sheet_id: int | None) -> str:
    url = (
        f"https://docs.google.com/spreadsheets/d/{quote(spreadsheet_id, safe='')}/edit"
    )
    return url + (f"#gid={sheet_id}" if sheet_id is not None else "")


async def create_spreadsheet(cred, title: str) -> tuple[str, str, int | None]:
    """A new spreadsheet in the credential's Drive: ``(id, tab title, gid)``."""
    response = await cred.request(
        "POST", SHEETS_API, json={"properties": {"title": title}}
    )
    if response.status_code != 200:
        raise _sheets_failure(response, cred)
    data = response.json()
    # The first tab's title is locale-dependent ("Sheet1", "Feuille 1", ...).
    props = data["sheets"][0]["properties"]
    return data["spreadsheetId"], props["title"], props.get("sheetId")


async def find_tab(
    cred, spreadsheet_id: str, gid: int | None, sheet: str
) -> tuple[str, int | None]:
    """``(title, gid)`` of the tab to write: ``sheet`` by name, else the URL's
    gid, else the first tab."""
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
        raise ExportFailed("That spreadsheet has no sheets")
    if sheet:
        for props in tabs:
            if props["title"].casefold() == sheet.casefold():
                return props["title"], props.get("sheetId")
        raise ExportFailed(f"No sheet called {sheet!r} in that spreadsheet")
    if gid is not None:
        for props in tabs:
            if props.get("sheetId") == gid:
                return props["title"], gid
        raise ExportFailed(f"No sheet with gid {gid} in that spreadsheet")
    return tabs[0]["title"], tabs[0].get("sheetId")


async def clear_tab(cred, spreadsheet_id: str, title: str) -> None:
    response = await cred.request(
        "POST",
        f"{SHEETS_API}/{quote(spreadsheet_id, safe='')}/values/"
        + quote(quote_sheet_title(title), safe="")
        + ":clear",
        json={},
    )
    if response.status_code != 200:
        raise _sheets_failure(response, cred)


async def append_rows(
    cred, spreadsheet_id: str, title: str, values: list[list[Any]]
) -> None:
    """Append ``values`` below the tab's existing data, ``CHUNK_ROWS`` at a time."""
    url = (
        f"{SHEETS_API}/{quote(spreadsheet_id, safe='')}/values/"
        + quote(quote_sheet_title(title), safe="")
        + ":append"
    )
    written = 0
    for chunk in chunk_rows(values, CHUNK_ROWS):
        response = await cred.request(
            "POST",
            url,
            params={
                # RAW: never parse input as formulas (formula injection).
                "valueInputOption": "RAW",
                # Insert new rows rather than overwrite anything below.
                "insertDataOption": "INSERT_ROWS",
            },
            json={"majorDimension": "ROWS", "values": chunk},
        )
        if response.status_code != 200:
            raise _sheets_failure(response, cred, written)
        written += len(chunk)


# --- The page -------------------------------------------------------------------------

TEMPLATE = """
{% extends "base.html" %}
{% block title %}Export to Google Sheets{% endblock %}
{% block content %}
<h1>Export {% if form.table %}{{ form.table }}{% else %}query results{% endif %}
  from {{ form.database }} to Google Sheets</h1>

{% if form.sql %}<pre>{{ form.sql }}</pre>{% endif %}

{% if done %}
<div class="message-info">
  <p>Exported {{ done.rows }} rows to
    <a href="{{ done.url }}">{{ done.url }}</a> (sheet {{ done.tab }}).</p>
</div>
{% endif %}

{% if error %}
<div class="message-error">
  <p>{{ error }}</p>
  {% if share_with %}
  <p>Share this sheet with <strong><code>{{ share_with }}</code></strong>
    as <strong>Editor</strong>, then try again.</p>
  {% endif %}
  {% if reconnect_url %}
  <p><a href="{{ reconnect_url }}">Reconnect Google</a> to fix this.</p>
  {% endif %}
</div>
{% endif %}

<form class="core" method="post" action="{{ action }}">
  <input type="hidden" name="database" value="{{ form.database }}">
  {% if form.table %}<input type="hidden" name="table" value="{{ form.table }}">{% endif %}
  {% if form.sql %}<input type="hidden" name="sql" value="{{ form.sql }}">{% endif %}
  {% if form.params %}<input type="hidden" name="params" value="{{ form.params }}">{% endif %}
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
    <label><input type="radio" name="target" value="new"
      {%- if form.target == "new" %} checked{% endif %}> New spreadsheet</label>
    <label for="title">titled</label>
    <input type="text" id="title" name="title" value="{{ form.title }}">
  </p>
  <p>
    <label><input type="radio" name="target" value="existing"
      {%- if form.target == "existing" %} checked{% endif %}> Existing spreadsheet</label>
    <input type="text" id="url" name="url" size="80" value="{{ form.url }}"
      placeholder="https://docs.google.com/spreadsheets/d/.../edit#gid=0">
  </p>
  <p>
    <label for="sheet">Sheet (optional)</label>
    <input type="text" id="sheet" name="sheet" value="{{ form.sheet }}"
      placeholder="defaults to the tab in the URL, or the first tab">
    <label><input type="radio" name="mode" value="replace"
      {%- if form.mode == "replace" %} checked{% endif %}> Replace its contents</label>
    <label><input type="radio" name="mode" value="append"
      {%- if form.mode == "append" %} checked{% endif %}> Append below them</label>
  </p>
  <p>
    <label><input type="checkbox" name="headers" value="1"
      {%- if form.headers %} checked{% endif %}> Include a header row</label>
  </p>
  <p><input type="submit" value="Export"></p>
</form>
<p>Service accounts can't create new spreadsheets. To export with one, create
the spreadsheet yourself, share it with the service account's email address as
<strong>Editor</strong>, and choose "Existing spreadsheet".</p>
<p>Values are written exactly as stored: text that looks like a formula is not
evaluated. At most {{ max_rows }} rows.</p>
{% endblock %}
"""


def _here(datasette, form: dict[str, Any]) -> str:
    """This page's path with the source in the query string (for return_to)."""
    args = {"database": form["database"]}
    for key in ("table", "sql", "params"):
        if form.get(key):
            args[key] = form[key]
    return datasette.urls.path(PATH) + "?" + urlencode(args)


async def _render(
    datasette,
    request,
    form: dict[str, Any],
    *,
    status: int = 200,
    failure: ExportFailed | None = None,
    done: dict[str, Any] | None = None,
) -> Response:
    credentials = await list_credentials(
        datasette, actor=request.actor, scopes=[SPREADSHEETS]
    )
    template = datasette.get_jinja_environment(request).from_string(TEMPLATE)
    html = await datasette.render_template(
        template,
        {
            "action": datasette.urls.path(PATH),
            "connect": connect_url(datasette, return_to=_here(datasette, form)),
            "credentials": credentials,
            "form": form,
            "done": done,
            "max_rows": f"{MAX_ROWS:,}",
            "error": failure.message if failure else None,
            "share_with": failure.share_with if failure else None,
            "reconnect_url": failure.reconnect_url if failure else None,
        },
        request=request,
    )
    return Response.html(html, status=status)


def _from_auth_error(
    datasette, form: dict[str, Any], error: GoogleAuthError
) -> ExportFailed:
    """Show any broker error; offer a reconnect that comes back here when
    reconnecting can fix it."""
    reconnect = None
    if isinstance(error, MissingScopes | CredentialBroken) and error.reconnect_url:
        reconnect = connect_url(datasette, return_to=_here(datasette, form))
    # error_response() is the broker's own status mapping (404, 403, 409, ...).
    return ExportFailed(
        str(error), status=error_response(error).status, reconnect_url=reconnect
    )


def _params(text: str) -> dict[str, str]:
    if not text:
        return {}
    try:
        params = json.loads(text)
    except ValueError:
        params = None
    if not isinstance(params, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in params.items()
    ):
        raise ExportFailed("Invalid query parameters")
    return params


async def _export(datasette, request, form: dict[str, Any]) -> dict[str, Any]:
    """Run the export; return what to show. Raises ``ExportFailed``."""
    actor = request.actor
    params = _params(form["params"])
    if not form["credential"]:
        raise ExportFailed("Choose a Google account")
    if form["target"] not in ("new", "existing"):
        raise ExportFailed("Choose a new or an existing spreadsheet")
    if form["mode"] not in ("replace", "append"):
        raise ExportFailed("Choose whether to replace or append")
    spreadsheet_id, gid = None, None
    if form["target"] == "existing":
        try:
            spreadsheet_id, gid = parse_sheet_url(form["url"])
        except ValueError as error:
            raise ExportFailed(str(error)) from None
    title = form["title"].strip() or form["table"] or "Datasette query"

    try:
        cred = await get_credential(
            datasette, form["credential"], actor=actor, scopes=[SPREADSHEETS]
        )
    except GoogleAuthError as error:
        raise _from_auth_error(datasette, form, error) from None
    if form["target"] == "new" and cred.info.type == "service_account":
        # D28: the file would live in the service account's own Drive.
        raise ExportFailed(
            "Service accounts can't create new spreadsheets: the file would be "
            "owned by the service account, where you can't see it. Create the "
            "spreadsheet yourself, share it with "
            f"{cred.info.google_email} as Editor, and choose "
            '"Existing spreadsheet".',
            share_with=cred.info.google_email,
        )

    # Read as the actor: core enforces view-table / execute-sql.
    columns, rows = await read_rows(
        datasette,
        actor,
        form["database"],
        table=form["table"] or None,
        sql=form["sql"] or None,
        params=params,
    )
    check_caps(columns, rows, header=form["headers"])
    values = [[cell_value(v) for v in row] for row in rows]
    if form["headers"]:
        values.insert(0, list(columns))

    try:
        if spreadsheet_id is None:
            spreadsheet_id, tab, gid = await create_spreadsheet(cred, title)
        else:
            tab, gid = await find_tab(cred, spreadsheet_id, gid, form["sheet"].strip())
            if form["mode"] == "replace":
                await clear_tab(cred, spreadsheet_id, tab)
        if values:
            await append_rows(cred, spreadsheet_id, tab, values)
    except GoogleAuthError as error:
        raise _from_auth_error(datasette, form, error) from None
    return {
        "rows": f"{len(rows):,}",
        "tab": tab,
        "url": _spreadsheet_url(spreadsheet_id, gid),
    }


async def export_page(datasette, request):
    posted = request.method == "POST"
    args = await request.post_vars() if posted else request.args
    form = {
        "database": args.get("database") or "",
        "table": args.get("table") or "",
        "sql": args.get("sql") or "",
        "params": args.get("params") or "",
        "credential": args.get("credential") or "",
        "target": args.get("target") or "new",
        "title": args.get("title") or "",
        "url": args.get("url") or "",
        "sheet": args.get("sheet") or "",
        "mode": args.get("mode") or "replace",
        "headers": bool(args.get("headers")) if posted else True,
    }
    database, table = form["database"], form["table"]
    if database not in datasette.databases:
        raise NotFound(f"Database not found: {database}")
    if bool(table) == bool(form["sql"]):
        raise NotFound("Export a table or a query: pass table= or sql=")
    if request.actor is None:
        raise Forbidden("Sign in to export to Google Sheets")

    if not posted:
        # A courtesy check so the form isn't offered for something the actor
        # can't read. The real enforcement is reading as the actor on submit.
        if table:
            ok = await datasette.allowed(
                action="view-table",
                resource=TableResource(database, table),
                actor=request.actor,
            )
        else:
            ok = await datasette.allowed(
                action="execute-sql",
                resource=DatabaseResource(database),
                actor=request.actor,
            )
        if not ok:
            raise Forbidden("You can't read that")
        return await _render(datasette, request, form)

    try:
        done = await _export(datasette, request, form)
    except ExportFailed as failure:
        return await _render(
            datasette, request, form, status=failure.status, failure=failure
        )
    return await _render(datasette, request, form, done=done)


# --- Hooks ------------------------------------------------------------------------------


def _action(datasette, **args: str) -> list[dict[str, str]]:
    return [
        {
            "href": datasette.urls.path(PATH) + "?" + urlencode(args),
            "label": "Export to Google Sheets",
            "description": "Write these rows to a new or existing Google Sheet",
        }
    ]


@hookimpl
def register_routes():
    return [(rf"^{PATH}$", export_page)]


@hookimpl
def table_actions(datasette, actor, database, table, request):
    if actor is None:
        return []
    return _action(datasette, database=database, table=table)


@hookimpl
def query_actions(datasette, actor, database, query_name, request, sql, params):
    # Stored queries have their own permission (view-query); exporting them as
    # sql= would need execute-sql instead. Only arbitrary SQL is offered.
    if actor is None or query_name is not None or not sql:
        return []
    args = {"database": database, "sql": sql}
    if params:
        args["params"] = json.dumps(params)
    return _action(datasette, **args)
