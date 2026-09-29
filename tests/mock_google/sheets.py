"""A minimal, mutable Sheets model: just enough for the importer and exporter
samples (tickets 16/17).

Cells hold plain JSON values (str, int, float, bool). Writes store values
as given whatever ``valueInputOption`` says: the mock never evaluates
formulas. Tests assert the option through the request log.

Ranges: ``Sheet1!A1:C3``, ``'My Sheet'!A2:C``, ``Sheet1!A:C``, ``Sheet1!2:5``,
``Sheet1`` (whole sheet) and bare ``A1:C3`` (first sheet). Sheet titles match
case-insensitively. Named ranges are not supported.

Fixture spreadsheets (a fresh copy per mock):

| id        | access                                 | contents                        |
|-----------|----------------------------------------|---------------------------------|
| students  | user@ writer, sa-test@ writer          | `students`, `assignments` tabs  |
| ragged    | user@ writer, sa-test@ writer          | ragged rows, blank/dup headers  |
| readonly  | user@ reader, sa-test@ reader          | for "share as Editor" errors    |
| private   | someone-else@ only                     | for "share with ..." errors     |
"""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass, field
from typing import Any

from .keys import SA_TEST
from .oauth import DEFAULT_USER

READER = "reader"
WRITER = "writer"
DEFAULT_ROWS = 1000
DEFAULT_COLUMNS = 26
MAX_COLUMN_LETTERS = 3


class RangeError(ValueError):
    """Maps to Google's 400 ``Unable to parse range: ...``."""


class GridLimitError(ValueError):
    """A range that starts outside the sheet's grid."""


@dataclass(frozen=True)
class Box:
    """0-based, half-open. ``None`` ends are open (to the edge of the grid)."""

    r0: int = 0
    c0: int = 0
    r1: int | None = None
    c1: int | None = None


WHOLE = Box()


def column_index(letters: str) -> int:
    n = 0
    for ch in letters.upper():
        n = n * 26 + ord(ch) - ord("A") + 1
    return n - 1


def column_letters(index: int) -> str:
    out = ""
    index += 1
    while index:
        index, rem = divmod(index - 1, 26)
        out = chr(ord("A") + rem) + out
    return out


_ENDPOINT = re.compile(r"^\$?([A-Za-z]{0,3})\$?([0-9]*)$")


def _endpoint(text: str) -> tuple[int | None, int | None]:
    match = _ENDPOINT.match(text)
    if not match or not (match.group(1) or match.group(2)):
        raise RangeError(text)
    letters, digits = match.groups()
    col = column_index(letters) if letters else None
    row = int(digits) - 1 if digits else None
    if row is not None and row < 0:
        raise RangeError(text)
    return row, col


def parse_a1(text: str) -> Box:
    """``B3``, ``A1:C4``, ``A:C``, ``A2:C``, ``2:5``."""
    parts = text.split(":")
    if len(parts) == 1:
        row, col = _endpoint(text)
        if row is None or col is None:
            raise RangeError(text)
        return Box(row, col, row + 1, col + 1)
    if len(parts) != 2:
        raise RangeError(text)
    (sr, sc), (er, ec) = _endpoint(parts[0]), _endpoint(parts[1])
    # Both ends name columns, or neither does (2:5).
    if (sc is None) != (ec is None):
        raise RangeError(text)
    box = Box(
        sr or 0,
        sc or 0,
        er + 1 if er is not None else None,
        ec + 1 if ec is not None else None,
    )
    if (box.r1 is not None and box.r1 <= box.r0) or (
        box.c1 is not None and box.c1 <= box.c0
    ):
        raise RangeError(text)
    return box


def split_sheet(text: str) -> tuple[str | None, str | None]:
    """``'My Sheet'!A1`` -> ("My Sheet", "A1"); ``A1`` -> (None, "A1")."""
    if text.startswith("'"):
        match = re.match(r"^'((?:[^']|'')+)'(?:!(.+))?$", text)
        if not match:
            raise RangeError(text)
        return match.group(1).replace("''", "'"), match.group(2)
    if "!" in text:
        sheet, _, rest = text.partition("!")
        if not sheet or not rest:
            raise RangeError(text)
        return sheet, rest
    return None, text


def quote_title(title: str) -> str:
    if re.fullmatch(r"[A-Za-z0-9_]+", title):
        return title
    return "'" + title.replace("'", "''") + "'"


@dataclass
class Sheet:
    title: str
    sheet_id: int
    index: int
    cells: dict[tuple[int, int], Any] = field(default_factory=dict)
    row_count: int = DEFAULT_ROWS
    column_count: int = DEFAULT_COLUMNS

    @classmethod
    def from_rows(
        cls, title: str, sheet_id: int, index: int, rows: list[list]
    ) -> Sheet:
        cells = {
            (r, c): value
            for r, row in enumerate(rows)
            for c, value in enumerate(row)
            if value is not None
        }
        return cls(title, sheet_id, index, cells)

    def properties_json(self) -> dict:
        return {
            "sheetId": self.sheet_id,
            "title": self.title,
            "index": self.index,
            "sheetType": "GRID",
            "gridProperties": {
                "rowCount": self.row_count,
                "columnCount": self.column_count,
            },
        }

    def a1(self, r0: int, c0: int, r1: int, c1: int) -> str:
        """``Title!A1:C3`` for the half-open box (``Title!B2`` for one cell)."""
        start = f"{column_letters(c0)}{r0 + 1}"
        end = f"{column_letters(c1 - 1)}{r1}"
        cells = start if (r1 - r0, c1 - c0) == (1, 1) else f"{start}:{end}"
        return f"{quote_title(self.title)}!{cells}"

    def close(self, box: Box) -> tuple[int, int, int, int]:
        """Close open ends at the grid edge and clip to the grid."""
        if box.r0 >= self.row_count or box.c0 >= self.column_count:
            raise GridLimitError(
                f"Range exceeds grid limits. Max rows: {self.row_count}, "
                f"max columns: {self.column_count}"
            )
        r1 = min(box.r1 if box.r1 is not None else self.row_count, self.row_count)
        c1 = min(box.c1 if box.c1 is not None else self.column_count, self.column_count)
        return box.r0, box.c0, r1, c1

    def read(self, box: Box) -> tuple[str, list[list[Any]]]:
        """(range, values) like ``values.get``: trailing empties trimmed,
        empty cells inside a row as ``""``."""
        r0, c0, r1, c1 = self.close(box)
        rows: list[list[Any]] = []
        for r in range(r0, r1):
            row = [self.cells.get((r, c)) for c in range(c0, c1)]
            while row and row[-1] is None:
                row.pop()
            rows.append(["" if value is None else value for value in row])
        while rows and not rows[-1]:
            rows.pop()
        return self.a1(r0, c0, r1, c1), rows

    def write(self, r0: int, c0: int, values: list[list[Any]]) -> dict:
        """Write rows at (r0, c0), growing the grid. ``None`` leaves a cell
        unchanged, ``""`` clears it."""
        height = len(values)
        width = max((len(row) for row in values), default=0)
        written = 0
        for dr, row in enumerate(values):
            for dc, value in enumerate(row):
                if value is None:
                    continue
                key = (r0 + dr, c0 + dc)
                if value == "":
                    self.cells.pop(key, None)
                else:
                    self.cells[key] = value
                written += 1
        self.row_count = max(self.row_count, r0 + height)
        self.column_count = max(self.column_count, c0 + width)
        return {
            "updatedRange": self.a1(r0, c0, r0 + max(height, 1), c0 + max(width, 1)),
            "updatedRows": height,
            "updatedColumns": width,
            "updatedCells": written,
        }

    def clear(self, box: Box) -> str:
        r0, c0, r1, c1 = self.close(box)
        for key in [k for k in self.cells if r0 <= k[0] < r1 and c0 <= k[1] < c1]:
            del self.cells[key]
        return self.a1(r0, c0, r1, c1)

    def used_rows(self) -> int:
        return max((r for r, _ in self.cells), default=-1) + 1

    def used_columns(self) -> int:
        return max((c for _, c in self.cells), default=-1) + 1


@dataclass
class Spreadsheet:
    spreadsheet_id: str
    title: str
    sheets: list[Sheet]
    acl: dict[str, str]  # principal email -> READER | WRITER
    created_by: str | None = None

    def find_sheet(self, name: str) -> Sheet | None:
        for sheet in self.sheets:
            if sheet.title == name:
                return sheet
        for sheet in self.sheets:
            if sheet.title.casefold() == name.casefold():
                return sheet
        return None

    def resolve(self, text: str) -> tuple[Sheet, Box]:
        """A range string -> (sheet, box). Raises ``RangeError``."""
        if not text:
            raise RangeError(text)
        name, rest = split_sheet(text)
        if name is not None:
            sheet = self.find_sheet(name)
            if sheet is None:
                raise RangeError(text)
            return sheet, parse_a1(rest) if rest is not None else WHOLE
        # Bare token: A1 notation on the first sheet, else a sheet title.
        try:
            box = parse_a1(text)
        except RangeError:
            sheet = self.find_sheet(text)
            if sheet is None:
                raise
            return sheet, WHOLE
        return min(self.sheets, key=lambda s: s.index), box

    def metadata_json(self) -> dict:
        return {
            "spreadsheetId": self.spreadsheet_id,
            "properties": {"title": self.title, "locale": "en_US"},
            "sheets": [{"properties": s.properties_json()} for s in self.sheets],
            "spreadsheetUrl": (
                f"https://docs.google.com/spreadsheets/d/{self.spreadsheet_id}/edit"
            ),
        }


# --- fixtures ------------------------------------------------------------------

USER = DEFAULT_USER.email
EDITORS = {USER: WRITER, SA_TEST: WRITER}


def build_fixtures() -> dict[str, Spreadsheet]:
    students = Sheet.from_rows(
        "students",
        0,
        0,
        [
            ["id", "name", "grade_level", "email"],
            [1, "Alice Chen", 10, "alice@school.edu"],
            [2, "Bob Jones", 11, "bob@school.edu"],
            [3, "Clara Smith", 10, "clara@school.edu"],
            [4, "David Kim", 12, "david@school.edu"],
            [5, "Eva Lopez", 11, "eva@school.edu"],
        ],
    )
    assignments = Sheet.from_rows(
        "assignments",
        1001,
        1,
        [
            ["id", "title", "max_score"],
            [101, "Essay: Modern Poetry", 100],
            [102, "Lab: Chemical Reactions", 50.5],
        ],
    )
    ragged = Sheet.from_rows(
        "data",
        0,
        0,
        [
            ["name", None, "name", "score"],  # blank and duplicate headers
            ["alice", "x", "a2", 10],
            ["bob"],  # short row
            [],  # empty middle row
            ["carol", None, None, 30, "extra"],  # gaps, wider than header
        ],
    )
    fixtures = [
        Spreadsheet("students", "Students", [students, assignments], dict(EDITORS)),
        Spreadsheet("ragged", "Ragged", [ragged], dict(EDITORS)),
        Spreadsheet(
            "readonly",
            "Read only",
            [Sheet.from_rows("Sheet1", 0, 0, [["k", "v"], ["a", 1]])],
            {USER: READER, SA_TEST: READER},
        ),
        Spreadsheet(
            "private",
            "Private",
            [Sheet.from_rows("Sheet1", 0, 0, [["secret"]])],
            {"someone-else@example.com": WRITER},
        ),
    ]
    return {ss.spreadsheet_id: ss for ss in fixtures}


class SpreadsheetStore:
    def __init__(self) -> None:
        self.spreadsheets = build_fixtures()

    def get(self, spreadsheet_id: str) -> Spreadsheet | None:
        return self.spreadsheets.get(spreadsheet_id)

    def create(self, title: str, sheet_titles: list[str], owner: str) -> Spreadsheet:
        spreadsheet_id = "mock" + secrets.token_urlsafe(30)
        sheets = [
            Sheet(title=name, sheet_id=0 if i == 0 else 1000 + i, index=i)
            for i, name in enumerate(sheet_titles or ["Sheet1"])
        ]
        ss = Spreadsheet(
            spreadsheet_id, title, sheets, {owner: WRITER}, created_by=owner
        )
        self.spreadsheets[spreadsheet_id] = ss
        return ss
