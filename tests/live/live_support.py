"""Names shared by tests/live/conftest.py and test_live.py (a conftest can't be
imported by name here: tests/conftest.py is also ``conftest``)."""

from __future__ import annotations

import re

KEY_ENV = "DATASETTE_GOOGLE_AUTH_LIVE_SA_KEY"
SHEET_ENV = "DATASETTE_GOOGLE_AUTH_LIVE_SHEET"

ALICE = {"id": "alice"}

SHEETS_API = "https://sheets.googleapis.com/v4/spreadsheets"
SHEETS = "https://www.googleapis.com/auth/spreadsheets"
SHEETS_READONLY = "https://www.googleapis.com/auth/spreadsheets.readonly"


class SecretText(str):
    """Key-file text that never shows itself in a repr (assertion output,
    tracebacks, ``--showlocals``)."""

    def __repr__(self) -> str:
        return "<SecretText redacted>"


def spreadsheet_id(value: str) -> str:
    """The ID from a spreadsheet URL, or ``value`` itself if it's a bare ID."""
    match = re.search(r"/spreadsheets/d/([A-Za-z0-9_-]+)", value)
    return match.group(1) if match else value
