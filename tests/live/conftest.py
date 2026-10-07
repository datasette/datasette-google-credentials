"""Opt-in live tests against real Google (wiki D17). See tests/live/SETUP.md.

Run with `just test-live`. `just test` never collects this directory
(`norecursedirs` in pyproject.toml), and without both environment variables
every test here is skipped, with a line saying which one is missing:

    DATASETTE_GOOGLE_CREDENTIALS_LIVE_SA_KEY   path to a service-account JSON key file
    DATASETTE_GOOGLE_CREDENTIALS_LIVE_SHEET    URL or ID of a spreadsheet shared with
                                        that key's client_email as Editor

The key is read from the file, never from the environment itself, and never
printed: fixtures hand it around as ``SecretText``, whose repr is redacted,
so a failing assertion or traceback can't show it. Tests must not assert on
access tokens either (pytest would print the value on failure).

These tests use the public API (``add_service_account``, ``get_credential``,
``Credential.request``, ``service.delete``) with the plugin's default Google
URLs and no injected transport, so every call goes to Google.
"""

from __future__ import annotations

import json
import os
import pathlib
import socket
from typing import Any

import pytest
import pytest_asyncio
from cryptography.fernet import Fernet
from datasette.app import Datasette
from live_support import ALICE, KEY_ENV, SHEET_ENV, SecretText, spreadsheet_id

from datasette_google_credentials import CredentialNotFound
from datasette_google_credentials.permissions import ADD_SERVICE_ACCOUNT
from datasette_google_credentials.service import delete
from datasette_google_credentials.service_account import add_service_account

HERE = pathlib.Path(__file__).resolve().parent


def _key_path() -> pathlib.Path | None:
    value = os.environ.get(KEY_ENV, "").strip()
    return pathlib.Path(value).expanduser() if value else None


def _sheet_value() -> str:
    return os.environ.get(SHEET_ENV, "").strip()


def _missing() -> str | None:
    """Why the live suite can't run, or None if it can. Names variables and
    the key's path, never the key's contents."""
    missing = [
        name for name in (KEY_ENV, SHEET_ENV) if not os.environ.get(name, "").strip()
    ]
    if missing:
        return (
            f"set {' and '.join(missing)} to run the live tests (tests/live/SETUP.md)"
        )
    path = _key_path()
    assert path is not None
    if not path.is_file():
        return f"{KEY_ENV} does not name a readable file: {path}"
    return None


def _is_live(item: pytest.Item) -> bool:
    return HERE in pathlib.Path(str(item.path)).resolve().parents


SKIP_REASON = pytest.StashKey[str]()


def pytest_collection_modifyitems(
    config: pytest.Config, items: list[pytest.Item]
) -> None:
    # Conftest collection hooks see every item in the session: only touch ours.
    live = [item for item in items if _is_live(item)]
    if not live:
        return
    reason = _missing()
    for item in live:
        item.add_marker(pytest.mark.live)
        if reason:
            item.add_marker(pytest.mark.skip(reason=reason))
    if reason:
        config.stash[SKIP_REASON] = reason


def pytest_terminal_summary(terminalreporter: Any, config: pytest.Config) -> None:
    reason = config.stash.get(SKIP_REASON, None)
    if reason:
        terminalreporter.write_line(f"test-live: skipped everything: {reason}")


# --- Network -----------------------------------------------------------------


@pytest.fixture(autouse=True, scope="session")
def _block_network():
    """Overrides tests/fixtures_google.py's autouse network block for this
    directory: these tests exist to reach Google.

    The block is session-scoped, so if a default-suite test ran earlier in
    the same session it is still in force. Say so rather than failing with
    ``NetworkBlocked`` deep inside a token exchange.
    """
    if getattr(socket.getaddrinfo, "__module__", "socket") != "socket":
        pytest.fail(
            "the default suite's network block is active: run the live tests "
            "on their own with `just test-live`",
            pytrace=False,
        )
    yield


# --- Inputs ------------------------------------------------------------------


@pytest.fixture(scope="session")
def live_key() -> SecretText:
    """The service-account key file's text (redacted repr)."""
    path = _key_path()
    assert path is not None
    return SecretText(path.read_text())


@pytest.fixture(scope="session")
def live_key_fields(live_key: SecretText) -> dict[str, str]:
    """The key file's non-secret fields, for comparisons."""
    data = json.loads(live_key)
    return {
        name: data[name]
        for name in ("client_email", "client_id", "private_key_id", "project_id")
        if isinstance(data.get(name), str)
    }


@pytest.fixture(scope="session")
def sheet_id() -> str:
    return spreadsheet_id(_sheet_value())


# --- Datasette + credential ----------------------------------------------------


@pytest_asyncio.fixture
async def datasette() -> Datasette:
    """A Datasette with a throwaway encryption key and the plugin's default
    (real) Google URLs. ``alice`` may add service accounts."""
    datasette = Datasette(
        memory=True,
        config={
            "plugins": {
                "datasette-google-credentials": {
                    "encryption-key": Fernet.generate_key().decode(),
                },
            },
            "permissions": {ADD_SERVICE_ACCOUNT: {"id": "alice"}},
        },
    )
    await datasette.invoke_startup()
    return datasette


@pytest_asyncio.fixture
async def credential(datasette: Datasette, live_key: SecretText):
    """The live key, added through ``add_service_account`` (which does a real
    test exchange first). Deleted afterwards if the test didn't."""
    info = await add_service_account(datasette, ALICE, live_key, "live test")
    yield info
    try:
        await delete(datasette, ALICE, info.id)
    except CredentialNotFound:
        pass
