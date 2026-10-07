"""Cross-cutting security invariants (ticket 22).

Each test here checks one invariant end to end, across modules, rather than
one module's behaviour:

* secrets never reach a response, page data, event, log line or core debug
  view, and are never stored in plaintext (scans the mock's actually issued
  tokens and codes, the key material and the configured secrets, plus the
  shapes ``-----BEGIN``, ``ya29.``, ``1//`` and Fernet ciphertext);
* ``Credential.request()`` sends the bearer token only to Google (D34);
* OAuth access never goes through ``datasette.allowed()`` (D6, D19);
* ``get_credential`` / ``token()`` re-read the row, whatever the cache holds;
* unknown ids and other people's ids are indistinguishable on the API, and
  do the same permission work (ticket 24);
* every POST is CSRF-protected, ``return_to`` can't redirect off-site;
* every outbound client has timeouts; labels are escaped in every page;
* removing or changing ``encryption-key`` after credentials exist fails
  clearly, without breaking startup.

Google doesn't document token prefixes (its OAuth 2.0 page gives only size
limits), so ``ya29.`` / ``1//`` are unverified shapes; the scans also look
for the exact values the mock issued, which is what makes them reliable.
"""

import ast
import dataclasses
import json
import logging
import re
import time
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs, urlencode, urlsplit

import httpx2
import pytest
from cryptography.fernet import Fernet
from datasette import hookimpl
from datasette.app import Datasette
from datasette.plugins import pm
from datasette_acl.grants import Principal, grant
from mock_google import MOCK_BASE, SHEETS_BASE
from mock_google.oauth import (
    OAUTH_CLIENT_SECRET,
    SCOPE_EMAIL,
    SCOPE_OPENID,
    SCOPE_SHEETS,
    GoogleUser,
)

from datasette_google_credentials import (
    CredentialBroken,
    CredentialForbidden,
    CredentialNotFound,
    CredentialUndecryptable,
    DisallowedHost,
    EncryptionNotConfigured,
    error_response,
    get_credential,
    list_credentials,
)
from datasette_google_credentials import service as service_module
from datasette_google_credentials import service_account as service_account_module
from datasette_google_credentials.broker import check_request_url
from datasette_google_credentials.crypto import encrypt_secret
from datasette_google_credentials.http import client as http_client
from datasette_google_credentials.internal_db import InternalDB
from datasette_google_credentials.oauth import (
    FLOW_COOKIE,
    FLOW_COOKIE_NAMESPACE,
    FlowState,
    safe_return_to,
    sign_state,
)
from datasette_google_credentials.permissions import (
    ADD_SERVICE_ACCOUNT,
    ADMIN,
    CONNECT,
    DECOY_SA_ID,
    RESOURCE_TYPE,
)
from datasette_google_credentials.router import router
from datasette_google_credentials.service import add_service_account
from datasette_google_credentials.token_cache import get_token_cache

ROOT_DIR = Path(__file__).resolve().parent.parent
PACKAGE_DIR = ROOT_DIR / "datasette_google_credentials"

ALICE = {"id": "alice"}
BOB = {"id": "bob"}
ADMIN_ACTOR = {"id": "admin"}
ALL_SCOPES = [SCOPE_OPENID, SCOPE_EMAIL, SCOPE_SHEETS]
API = "/-/google-credentials/api"
STUDENTS = f"{SHEETS_BASE}/v4/spreadsheets/students"
SAME_ORIGIN = {"Sec-Fetch-Site": "same-origin"}
UNKNOWN_ID = "01JZZZZZZZZZZZZZZZZZZZZZZZ"

# Shapes of Google secrets and of our ciphertext. The token prefixes are
# unverified (see the module docstring); the exact-value scan doesn't need them.
SECRET_PATTERNS = [
    re.compile(r"-----BEGIN"),
    re.compile(r"ya29\."),
    re.compile(r"(?<![\w/])1//[A-Za-z0-9_-]"),
    re.compile(r"gAAAAA[A-Za-z0-9_=-]{20,}"),  # Fernet token
]

# Mock request form fields that carry a secret.
SECRET_FORM_FIELDS = {
    "code",
    "code_verifier",
    "refresh_token",
    "assertion",
    "token",
    "client_secret",
}


# --- Fixtures and helpers -----------------------------------------------------


async def make_datasette(mock_google, *, key=None, plugin_config=None, **kwargs):
    config = {"encryption-key": key or Fernet.generate_key().decode()}
    config.update(plugin_config or {})
    datasette = mock_google.datasette(
        plugin_config=config,
        config={
            "permissions": {
                CONNECT: {"id": ["alice", "bob"]},
                ADD_SERVICE_ACCOUNT: {"id": "alice"},
                ADMIN: {"id": "admin"},
            }
        },
        **kwargs,
    )
    await datasette.invoke_startup()
    return datasette


def idb(datasette) -> InternalDB:
    return InternalDB(datasette.get_internal_database())


def raw(key) -> str:
    return json.dumps(key.key_json())


async def add_sa(datasette, service_account_keys, name="test"):
    return await add_service_account(
        datasette, ALICE, raw(service_account_keys[name]), ""
    )


async def add_oauth(datasette, mock_google, owner="alice", subject="sub-1"):
    refresh_token = mock_google.oauth.issue_refresh_token(scopes=frozenset(ALL_SCOPES))
    row, _ = await idb(datasette).upsert_oauth(
        owner,
        subject,
        google_email=f"{owner}-{subject}@example.com",
        label=f"{owner}-{subject}",
        scopes=ALL_SCOPES,
        secret_encrypted=encrypt_secret(datasette, {"refresh_token": refresh_token}),
        actor_id=owner,
    )
    return row


async def share(datasette, credential_id, role="User", actor_id="bob"):
    await grant(
        datasette,
        RESOURCE_TYPE,
        credential_id,
        principal=Principal.actor(actor_id),
        role=role,
        by_actor="alice",
    )


def path_and_query(url: str) -> str:
    parts = urlsplit(url)
    return parts.path + ("?" + parts.query if parts.query else "")


async def post(datasette, path, body=None, *, actor=ALICE):
    return await datasette.client.post(
        API + path, json=body, actor=actor, headers=SAME_ORIGIN
    )


class Connect:
    """Connect Google through the real routes and the mock's consent screen,
    remembering every flow secret (state, cookie, PKCE verifier, code)."""

    def __init__(self, datasette, mock_google):
        self.datasette = datasette
        self.mock_google = mock_google
        self.secrets: set[str] = set()

    async def authorize(self, actor=ALICE, return_to="/-/google-credentials"):
        response = await self.datasette.client.get(
            "/-/google-credentials/connect?" + urlencode({"return_to": return_to}),
            actor=actor,
        )
        assert response.status_code == 302
        cookie = response.cookies[FLOW_COOKIE]
        location = response.headers["location"]
        state = parse_qs(urlsplit(location).query)["state"][0]
        verifier = self.datasette.unsign(cookie, namespace=FLOW_COOKIE_NAMESPACE)["v"]
        self.secrets |= {cookie, state, verifier}
        async with self.mock_google.client() as google:
            consent = await google.get(location)
        callback_url = consent.headers["location"]
        code = parse_qs(urlsplit(callback_url).query).get("code")
        if code:
            self.secrets.add(code[0])
        return callback_url, cookie

    async def callback(self, callback_url, cookie, actor=ALICE):
        return await self.datasette.client.get(
            path_and_query(callback_url), actor=actor, cookies={FLOW_COOKIE: cookie}
        )

    async def connect(self, actor=ALICE):
        return await self.callback(*await self.authorize(actor), actor=actor)


class EventRecorder:
    def __init__(self):
        self.events = []

    @hookimpl
    def track_event(self, datasette, event):
        self.events.append(event)


@pytest.fixture
def events():
    recorder = EventRecorder()
    pm.register(recorder, name="security-invariants-events")
    try:
        yield recorder.events
    finally:
        pm.unregister(name="security-invariants-events")


def key_material(service_account_keys) -> set[str]:
    """PEMs, a chunk of each key body and a slice of an RSA line: things
    that are secret. (client_email, project_id and private_key_id are shown
    to users by design, so they aren't here.)"""
    found = set()
    for key in service_account_keys.values():
        pem = key.private_key_pem
        body = "".join(line for line in pem.splitlines() if "-----" not in line)
        found |= {pem, body[100:140], body[-80:-40]}
    return found


def harvested_secrets(mock_google) -> set[str]:
    """Every secret the mock issued or received."""
    found = set(mock_google.tokens.issued_tokens())
    found |= set(mock_google.oauth.refresh_tokens())
    for request in mock_google.requests:
        for name, value in (request.form or {}).items():
            if name in SECRET_FORM_FIELDS:
                found.add(value)
        authorization = request.headers.get("authorization")
        if authorization:
            found.add(authorization.partition(" ")[2])
    return {value for value in found if value}


def leaks(text: str, secrets: set[str]) -> list[str]:
    """What in ``text`` looks like, or is, a secret. Described by pattern or
    length only, so a failing assertion never prints the secret."""
    found = [f"pattern {p.pattern}" for p in SECRET_PATTERNS if p.search(text)]
    found += [
        f"a secret value ({len(s)} chars)"
        for s in secrets
        if s and len(s) >= 8 and s in text
    ]
    return found


def response_text(response) -> str:
    """Headers and body of an httpx2 response (from ``datasette.client``) or
    a Datasette ``Response`` (from ``error_response``)."""
    headers = "\n".join(f"{k}: {v}" for k, v in response.headers.items())
    if isinstance(response, httpx2.Response):
        body = response.text
    else:
        body = response.body
        body = body.decode() if isinstance(body, bytes) else body
    return headers + "\n\n" + body


# --- The workload ---------------------------------------------------------------


async def run_flows(datasette, mock_google, service_account_keys, monkeypatch):
    """Representative happy and failure paths through every surface.

    Returns ``(responses, flow_secrets)``. ``responses`` excludes only the
    connect redirect, which carries the signed state and flow cookie to the
    browser by design (D24)."""
    responses = []

    async def keep(response):
        responses.append(response)
        return response

    connect = Connect(datasette, mock_google)
    mock_google.oauth.rotate_refresh_tokens = True
    mock_google.oauth.user = GoogleUser("sub-scan", "scan@example.com")

    # Service accounts through the API: add, a bad key that looks like a PEM,
    # a key for another account, an unexpected error while handling a key.
    added = await keep(
        await post(
            datasette,
            "/service-accounts",
            {"key_json": raw(service_account_keys["test"])},
        )
    )
    assert added.status_code == 200
    sa_id = added.json()["id"]
    fake_pem = "-----BEGIN PRIVATE KEY-----\nNOT-A-KEY-SENTINEL-XYZZY\n-----END PRIVATE KEY-----"
    bad = dict(service_account_keys["test"].key_json(), private_key=fake_pem)
    response = await keep(
        await post(datasette, "/service-accounts", {"key_json": json.dumps(bad)})
    )
    assert response.status_code == 400
    response = await keep(
        await post(
            datasette,
            f"/credentials/{sa_id}/rotate-key",
            {"key_json": raw(service_account_keys["other"])},
        )
    )
    assert response.status_code == 400

    def exploding_parse(raw_key):
        raise RuntimeError(f"parser choked on {raw_key}")

    with monkeypatch.context() as patch:
        patch.setattr(service_account_module, "parse_key", exploding_parse)
        response = await keep(
            await post(
                datasette,
                "/service-accounts",
                {"key_json": raw(service_account_keys["other"])},
            )
        )
    assert response.status_code == 500

    # The broker: token, request, a 401 retry, a disallowed host.
    sa = await get_credential(datasette, sa_id, actor=ALICE, scopes=[SCOPE_SHEETS])
    await sa.token()
    assert (await sa.request("GET", STUDENTS)).status_code == 200
    mock_google.faults.fail("/v4/spreadsheets/", 401, times=1)
    assert (await sa.request("GET", STUDENTS)).status_code == 200
    with pytest.raises(DisallowedHost) as disallowed:
        await sa.request("GET", "https://evil.example.com/steal")
    responses.append(error_response(disallowed.value))

    # Connect Google (created, reconnected), then a refresh that rotates.
    assert (await keep(await connect.connect())).status_code == 302
    assert (await keep(await connect.connect())).status_code == 302
    (oauth_row,) = [
        row
        for row in await idb(datasette).list_owned("alice")
        if row.type == "google_oauth"
    ]
    oauth = await get_credential(
        datasette, oauth_row.id, actor=ALICE, scopes=[SCOPE_SHEETS]
    )
    get_token_cache(datasette).evict(oauth_row.id)
    # The mock user hasn't been given this sheet: a 403 from "Google" is fine.
    assert (await oauth.request("GET", STUDENTS)).status_code in (200, 403)

    # Callback failures: tampered state, reused code, cancelled.
    callback_url, cookie = await connect.authorize()
    await keep(
        await connect.callback(callback_url.replace("state=", "state=x"), cookie)
    )
    assert (await keep(await connect.callback(callback_url, cookie))).status_code == 302
    assert (await keep(await connect.callback(callback_url, cookie))).status_code == 400
    mock_google.oauth.deny = True
    await keep(await connect.connect())
    mock_google.oauth.deny = False

    # Rename, list, status, both pages.
    await keep(
        await post(datasette, f"/credentials/{sa_id}/rename", {"label": "Renamed"})
    )
    for path, actor in (
        (f"{API}/credentials", ALICE),
        (f"{API}/credentials?scopes={SCOPE_SHEETS}", ALICE),
        (f"{API}/status", ALICE),
        ("/-/google-credentials", ALICE),
        ("/-/google-credentials/admin", ADMIN_ACTOR),
        (f"{API}/admin/credentials", ADMIN_ACTOR),
    ):
        response = await keep(await datasette.client.get(path, actor=actor))
        assert response.status_code == 200, path

    # Google revokes the grant: broken, and the consumer's error body.
    for token in mock_google.oauth.refresh_tokens():
        async with mock_google.client() as google:
            await google.post("/revoke", data={"token": token})
    get_token_cache(datasette).evict(oauth_row.id)
    with pytest.raises(CredentialBroken) as broken:
        await oauth.token()
    responses.append(error_response(broken.value))
    await keep(await datasette.client.get(f"{API}/credentials", actor=ALICE))

    # Delete both (an OAuth revoke at Google, a service-account key hint).
    mock_google.oauth.user = GoogleUser("sub-scan-2", "scan2@example.com")
    await connect.connect()
    for row in await idb(datasette).list_owned("alice"):
        response = await keep(await post(datasette, f"/credentials/{row.id}/delete"))
        assert response.status_code == 200
    return responses, connect.secrets


def all_secrets(datasette_key, mock_google, service_account_keys, flow_secrets):
    return (
        harvested_secrets(mock_google)
        | key_material(service_account_keys)
        | flow_secrets
        | {OAUTH_CLIENT_SECRET, datasette_key, "NOT-A-KEY-SENTINEL-XYZZY"}
    )


def log_lines(caplog) -> list[str]:
    formatter = logging.Formatter()
    lines = []
    for record in caplog.records:
        text = record.getMessage()
        if record.exc_info:
            text += "\n" + formatter.formatException(record.exc_info)
        if record.stack_info:
            text += "\n" + record.stack_info
        # The test harness's own requests into Datasette (and to the mock's
        # consent screen) carry codes and state in their URLs, as a real
        # browser's would; they aren't the plugin's logging.
        if record.name.startswith("httpx") and (
            "http://localhost/" in text or "/o/oauth2/v2/auth" in text
        ):
            continue
        lines.append(f"{record.name}: {text}")
    return lines


# --- Secrets ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_no_secret_in_responses_page_data_events_or_logs(
    mock_google, service_account_keys, events, caplog, monkeypatch
):
    caplog.set_level(logging.DEBUG)
    key = Fernet.generate_key().decode()
    datasette = await make_datasette(mock_google, key=key)
    responses, flow_secrets = await run_flows(
        datasette, mock_google, service_account_keys, monkeypatch
    )
    secrets = all_secrets(key, mock_google, service_account_keys, flow_secrets)
    # Sanity: the workload really exercised every kind of secret.
    assert any(s.startswith("ya29.mock-") for s in secrets)
    assert any(s.startswith("1//mock-") for s in secrets)
    assert any(s.startswith("4/mock-") for s in secrets)
    assert len(responses) > 20

    for number, response in enumerate(responses):
        text = response_text(response)
        found = leaks(text, secrets)
        assert not found, (f"response #{number}", found)
        # No GoogleCredentialsError escaped an API route (D29): every API answer is
        # the plugin's own JSON, errors in error_response()'s shape, never
        # core's 500 page (which would carry the exception message).
        if isinstance(
            response, httpx2.Response
        ) and response.request.url.path.startswith(API):
            path = response.request.url.path
            assert response.headers["content-type"].startswith("application/json"), path
            if response.status_code >= 400:
                assert response.json()["code"], path

    kinds = {event.name for event in events}
    assert {
        "google-credential-created",
        "google-credential-reconnected",
        "google-credential-broken",
        "google-credential-deleted",
    } <= kinds
    for event in events:
        text = repr(event) + json.dumps(event.properties(), default=str)
        found = leaks(text, secrets)
        assert not found, (event.name, found)

    lines = log_lines(caplog)
    # The unexpected-error path logged something (type and stack only).
    assert any("unexpected RuntimeError" in line for line in lines)
    for line in lines:
        found = leaks(line, secrets)
        assert not found, (line.partition(":")[0], found)


def test_error_response_shape_for_disallowed_host():
    error = DisallowedHost("https://evil.example.com", "evil.example.com", "nope")
    response = error_response(error)
    assert response.status == 400
    body = json.loads(response.body)
    assert body["code"] == "disallowed_host"
    assert body["ok"] is False


# Core routes that could conceivably show the internal database, plugin
# config or permission state (1.0a41 has no `/-/internal` view: the internal
# database isn't in `datasette.databases`, so it has no table/query/download
# routes at all).
DEBUG_PATHS = [
    "/-/internal",
    "/__INTERNAL__",
    "/__INTERNAL__.json",
    "/__INTERNAL__.db",
    "/__INTERNAL__/datasette_google_credentials.json",
    "/-/databases.json",
    "/-/config",
    "/-/config.json",
    "/-/settings.json",
    "/-/plugins.json",
    "/-/schema.json",
    "/-/actions.json",
    "/-/rules.json",
    "/-/allowed.json?action=google-service-account-use",
    "/-/permissions",
    "/-/threads.json",
    "/-/tasks.json",
    "/-/messages",
    "/-/debug/autocomplete",
    "/-/versions.json",
    "/-/queries.json",
    "/_memory/-/query.json?sql=select+*+from+datasette_google_credentials",
]


@pytest.mark.asyncio
async def test_core_debug_views_never_show_secrets(mock_google, service_account_keys):
    key = Fernet.generate_key().decode()
    datasette = await make_datasette(mock_google, key=key)
    datasette.root_enabled = True
    sa = await add_sa(datasette, service_account_keys)
    oauth_row = await add_oauth(datasette, mock_google)
    await (
        await get_credential(datasette, sa.id, actor=ALICE, scopes=[SCOPE_SHEETS])
    ).token()
    await (
        await get_credential(
            datasette, oauth_row.id, actor=ALICE, scopes=[SCOPE_SHEETS]
        )
    ).token()
    secrets = (
        harvested_secrets(mock_google)
        | key_material(service_account_keys)
        | {OAUTH_CLIENT_SECRET, key}
    )

    for path in DEBUG_PATHS:
        response = await datasette.client.get(path, actor={"id": "root"})
        assert response.status_code < 500, path
        found = leaks(response_text(response), secrets)
        assert not found, (path, found)
    for path in ("/-/internal", "/__INTERNAL__", "/__INTERNAL__.db"):
        response = await datasette.client.get(path, actor={"id": "root"})
        assert response.status_code == 404, path
    # /-/config redacts the plugin's secret-bearing keys.
    config = (await datasette.client.get("/-/config.json", actor={"id": "root"})).json()
    plugin = config["plugins"]["datasette-google-credentials"]
    assert plugin["encryption-key"] != key
    assert plugin["client_secret"] != OAUTH_CLIENT_SECRET


@pytest.mark.asyncio
async def test_secrets_are_never_stored_in_plaintext(
    mock_google, service_account_keys, tmp_path, monkeypatch
):
    """The internal database file (and its WAL) never holds a refresh token,
    an access token or key material: secrets are Fernet-encrypted and access
    tokens are never persisted (D7)."""
    internal = tmp_path / "internal.db"
    key = Fernet.generate_key().decode()
    datasette = await make_datasette(mock_google, key=key, internal=str(internal))
    _, flow_secrets = await run_flows(
        datasette, mock_google, service_account_keys, monkeypatch
    )
    # Leave some credentials behind (run_flows deletes its own).
    await add_sa(datasette, service_account_keys)
    oauth_row = await add_oauth(datasette, mock_google)
    await (
        await get_credential(
            datasette, oauth_row.id, actor=ALICE, scopes=[SCOPE_SHEETS]
        )
    ).token()
    secrets = (
        set(mock_google.tokens.issued_tokens())
        | set(mock_google.oauth.refresh_tokens())
        | key_material(service_account_keys)
        | {key, OAUTH_CLIENT_SECRET}
    )
    datasette.close()
    stored = b"".join(
        path.read_bytes()
        for path in tmp_path.iterdir()
        if path.name.startswith("internal.db")
    ).decode("latin-1")
    has_table = "datasette_google_credentials" in stored
    assert has_table
    # Booleans first: a failing `x not in stored` would print both strings.
    # (Not leaks(): the file is full of Fernet ciphertext, by design.)
    found = [f"{len(s)}-char secret" for s in secrets if s in stored]
    found += [shape for shape in ("-----BEGIN", "ya29.") if shape in stored]
    assert not found, found


def _strings(value, seen, depth=0):
    """Every string reachable from ``value`` through containers, dataclasses
    and object ``__dict__`` s (bounded)."""
    if depth > 8 or id(value) in seen:
        return
    if isinstance(value, Datasette | httpx2.AsyncBaseTransport):
        # The Datasette instance is walked through its _google_credentials_*
        # attributes only; the transport is the mock Google (which of course
        # holds the tokens it issued).
        return
    seen.add(id(value))
    if isinstance(value, str):
        yield value
    elif isinstance(value, bytes):
        yield value.decode("latin-1")
    elif isinstance(value, dict):
        for k, v in value.items():
            yield from _strings(k, seen, depth + 1)
            yield from _strings(v, seen, depth + 1)
    elif isinstance(value, (list, tuple, set, frozenset)):
        for item in value:
            yield from _strings(item, seen, depth + 1)
    elif dataclasses.is_dataclass(value) and not isinstance(value, type):
        for f in dataclasses.fields(value):
            yield from _strings(getattr(value, f.name), seen, depth + 1)
    elif hasattr(value, "__dict__") and not isinstance(value, type):
        yield from _strings(vars(value), seen, depth + 1)


@pytest.mark.asyncio
async def test_decrypted_secrets_are_not_retained(mock_google, service_account_keys):
    """No long-lived object the plugin owns (the Credential, the token
    cache, the touch throttle, the config, anything on ``datasette`` under
    ``_google_credentials_``) holds a decrypted key or refresh token after use."""
    datasette = await make_datasette(mock_google)
    sa = await add_sa(datasette, service_account_keys)
    oauth_row = await add_oauth(datasette, mock_google)
    held = []
    for credential_id in (sa.id, oauth_row.id):
        cred = await get_credential(
            datasette, credential_id, actor=ALICE, scopes=[SCOPE_SHEETS]
        )
        await cred.token()
        await cred.request("GET", STUDENTS)
        held.append(cred)
    plugin_state = {
        name: value
        for name, value in vars(datasette).items()
        if "google_credentials" in name
    }
    assert plugin_state  # the cache, the config, the throttle, the transport
    reachable = "\n".join(
        _strings([held, plugin_state, get_token_cache(datasette)], set())
    )
    secrets = set(mock_google.oauth.refresh_tokens()) | key_material(
        service_account_keys
    )
    held_secrets = [len(s) for s in secrets if s in reachable]
    assert held_secrets == [], "secrets of these lengths are still held"
    has_pem = "-----BEGIN" in reachable
    assert not has_pem


def test_config_repr_hides_secrets():
    from datasette_google_credentials.config import Config

    config = Config.model_validate(
        {"encryption-key": "KEY-SENTINEL", "client_secret": "SECRET-SENTINEL"}
    )
    assert "KEY-SENTINEL" not in repr(config)
    assert "SECRET-SENTINEL" not in repr(config)


# --- Outbound requests (D34) --------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        STUDENTS,
        "https://www.googleapis.com/drive/v3/files",
        "https://SHEETS.GoogleApis.com:443/v4/spreadsheets/students",
        "https://sheets.googleapis.com:8443/v4/spreadsheets/x",
        # The configured (mock) google_base_urls origin, http included.
        f"{MOCK_BASE}/v1/userinfo",
        httpx2.URL(STUDENTS),
    ],
)
@pytest.mark.asyncio
async def test_request_allows_google_hosts(mock_google, url):
    datasette = await make_datasette(mock_google)
    assert check_request_url(datasette, url).host


@pytest.mark.parametrize(
    "url",
    [
        "http://sheets.googleapis.com/v4/spreadsheets/students",
        "https://evil.example.com/v4/spreadsheets/students",
        "https://sheets.googleapis.com.evil.com/v4",
        "https://evil.com@sheets.googleapis.com/v4",
        "https://evil.com\\@sheets.googleapis.com/v4",
        "https://user:pw@sheets.googleapis.com/v4",
        "https://sheets.googleapis.com%2F@evil.com/v4",
        "https://evil.com#.googleapis.com",
        "https://evil.com?.googleapis.com",
        "https://evil.com/.googleapis.com",
        "https://evil。com/.googleapis.com",
        "https://googleapis.com/v4",
        "https://sheets.googleapis.com./v4",
        "https://notgoogleapis.com/v4",
        "ftp://sheets.googleapis.com/v4",
        "/v4/spreadsheets/students",
        "",
        # The mock's host, but not its configured origin.
        "https://mock-google/v1/userinfo",
        "http://mock-google:8080/v1/userinfo",
        "https://accounts.google.com.evil.com/",
    ],
)
@pytest.mark.asyncio
async def test_request_refuses_other_urls_before_fetching_a_token(
    mock_google, service_account_keys, url
):
    datasette = await make_datasette(mock_google)
    sa = await add_sa(datasette, service_account_keys)
    cred = await get_credential(datasette, sa.id, actor=ALICE, scopes=[SCOPE_SHEETS])
    before = len(mock_google.requests)
    with pytest.raises(DisallowedHost) as raised:
        await cred.request("GET", url, headers={"X-Test": "1"})
    # Nothing went anywhere, and no token was minted or cached.
    assert len(mock_google.requests) == before
    assert len(get_token_cache(datasette)) == 0
    assert raised.value.code == "disallowed_host"
    assert error_response(raised.value).status == 400


@pytest.mark.asyncio
async def test_disallowed_host_message_names_only_scheme_and_host(
    mock_google, service_account_keys
):
    datasette = await make_datasette(mock_google)
    with pytest.raises(DisallowedHost) as raised:
        check_request_url(
            datasette, "https://attacker:pw@evil.example.com/PATH-XYZ?q=QUERY-XYZ"
        )
    assert raised.value.host == "evil.example.com"
    for part in ("PATH-XYZ", "QUERY-XYZ", "attacker", ":pw"):
        assert part not in str(raised.value)


@pytest.mark.asyncio
async def test_allow_any_host_sends_anywhere(mock_google, service_account_keys):
    datasette = await make_datasette(mock_google)
    sa = await add_sa(datasette, service_account_keys)
    cred = await get_credential(datasette, sa.id, actor=ALICE, scopes=[SCOPE_SHEETS])
    response = await cred.request(
        "GET", "http://evil.example.com/steal", allow_any_host=True
    )
    # The mock answers 421 for hosts it doesn't serve; the point is the
    # request (with the token) was sent.
    assert response.status_code == 421
    (call,) = mock_google.calls("/steal", host="evil.example.com")
    assert call.headers["authorization"].startswith("Bearer ya29.")


@pytest.mark.asyncio
async def test_google_urls_come_only_from_config(mock_google, service_account_keys):
    """A key file's token_uri is ignored, and the plugin's own calls only go
    to the configured google_base_urls (the consumer's Sheets calls aside)."""
    datasette = await make_datasette(mock_google)
    key = dict(
        service_account_keys["test"].key_json(),
        token_uri="https://evil.example.com/token",
    )
    await add_service_account(datasette, ALICE, json.dumps(key), "")
    await Connect(datasette, mock_google).connect()
    hosts = {request.host for request in mock_google.requests}
    assert hosts <= {"mock-google"}
    # And no Google URL is hard-coded outside config.py (user-facing links
    # to Google's consoles and help pages aside).
    allowed_elsewhere = {
        "https://www.googleapis.com/auth/",  # scope names, not endpoints
        # Links shown to people, and documentation links in comments.
        "https://myaccount.google.com/linkedapps",
        "https://console.cloud.google.com/iam-admin/serviceaccounts",
        "https://docs.cloud.google.com/",
        "https://developers.google.com/",
        "https://support.google.com/",
    }
    for path in PACKAGE_DIR.rglob("*.py"):
        if path.name == "config.py":
            continue
        for url in re.findall(
            r"https?://[\w.-]*google[\w.-]*/[\w./-]*", path.read_text()
        ):
            assert any(url.startswith(ok) for ok in allowed_elsewhere), (path, url)


def test_every_outbound_client_has_timeouts_and_no_redirects():
    client = http_client(SimpleNamespace())  # ty: ignore[invalid-argument-type]
    timeout = client.timeout
    for part in ("connect", "read", "write", "pool"):
        assert getattr(timeout, part) is not None, part
    assert client.follow_redirects is False
    # http.client() is the only place an HTTP client is built, in the plugin
    # and in the samples (which only use Credential.request()).
    builders = []
    for path in [*PACKAGE_DIR.rglob("*.py"), *(ROOT_DIR / "samples").glob("*.py")]:
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import | ast.ImportFrom):
                names = [alias.name for alias in node.names]
                module = getattr(node, "module", None) or ""
                assert "httpx" not in names and not module.startswith("httpx."), path
                assert "requests" not in names and module != "requests", path
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in {"AsyncClient", "Client"}
            ):
                builders.append(path.relative_to(ROOT_DIR).as_posix())
    assert builders == ["datasette_google_credentials/http.py"]


# --- Access -------------------------------------------------------------------


@pytest.mark.asyncio
async def test_oauth_access_never_calls_allowed(mock_google, monkeypatch):
    """Even with a stray acl grant on an OAuth credential's id, nothing asks
    datasette.allowed()/allowed_many() about it, and only its owner can use
    it (root and google-credentials-admin included)."""
    datasette = await make_datasette(mock_google)
    datasette.root_enabled = True
    row = await add_oauth(datasette, mock_google)
    await grant(
        datasette,
        RESOURCE_TYPE,
        row.id,
        principal=Principal.actor("bob"),
        role="Manager",
        by_actor="root",
    )

    asked = []
    real_allowed, real_allowed_many = datasette.allowed, datasette.allowed_many

    async def spy_allowed(**kwargs):
        asked.append(kwargs.get("resource"))
        return await real_allowed(**kwargs)

    async def spy_allowed_many(**kwargs):
        asked.append(kwargs.get("resource"))
        return await real_allowed_many(**kwargs)

    monkeypatch.setattr(datasette, "allowed", spy_allowed)
    monkeypatch.setattr(datasette, "allowed_many", spy_allowed_many)

    for actor in (BOB, {"id": "root"}, ADMIN_ACTOR):
        with pytest.raises((CredentialNotFound, CredentialForbidden)):
            await get_credential(datasette, row.id, actor=actor, scopes=[SCOPE_SHEETS])
        assert await list_credentials(datasette, actor=actor) == []
    for path, body in (
        (f"/credentials/{row.id}/rename", {"label": "pwned"}),
        (f"/credentials/{row.id}/rotate-key", {"key_json": "{}"}),
        (f"/credentials/{row.id}/delete", None),
    ):
        response = await post(datasette, path, body, actor=BOB)
        assert response.status_code == 404, path
    listing = await datasette.client.get(f"{API}/credentials", actor=BOB)
    assert listing.json()["credentials"] == []

    cred = await get_credential(datasette, row.id, actor=ALICE, scopes=[SCOPE_SHEETS])
    assert (await cred.request("GET", STUDENTS)).status_code == 200
    page = await datasette.client.get("/-/google-credentials", actor=ALICE)
    assert page.status_code == 200

    assert asked  # global checks (admin, connect) did happen
    about_oauth = [r for r in asked if r is not None and row.id in {r.parent, r.child}]
    assert about_oauth == []
    assert (await idb(datasette).get(row.id)).label == row.label


@pytest.mark.asyncio
async def test_every_use_rereads_the_row_whatever_the_cache_holds(
    mock_google, service_account_keys, monkeypatch
):
    datasette = await make_datasette(mock_google)
    sa = await add_sa(datasette, service_account_keys)
    await share(datasette, sa.id)
    oauth_row = await add_oauth(datasette, mock_google)

    reads = []
    real_get = InternalDB.get

    async def counting_get(self, id):
        reads.append(id)
        return await real_get(self, id)

    monkeypatch.setattr(InternalDB, "get", counting_get)

    bob_sa = await get_credential(datasette, sa.id, actor=BOB, scopes=[SCOPE_SHEETS])
    alice_oauth = await get_credential(
        datasette, oauth_row.id, actor=ALICE, scopes=[SCOPE_SHEETS]
    )
    for cred in (bob_sa, alice_oauth):
        await cred.token()  # warm the cache
        before = len(reads)
        await cred.token()  # a cache hit...
        assert reads[before:] == [cred.id]  # ...still re-read the row

    # "Another process" breaks one and deletes the other, without touching
    # this process's token cache.
    row = await real_get(idb(datasette), sa.id)
    assert await idb(datasette).mark_broken(
        sa.id, "broken elsewhere", expected_secret=row.secret_encrypted
    )
    assert await idb(datasette).delete(oauth_row.id)
    assert len(get_token_cache(datasette)) == 2
    with pytest.raises(CredentialBroken):
        await bob_sa.token()
    with pytest.raises(CredentialBroken):
        await bob_sa.request("GET", STUDENTS)
    with pytest.raises(CredentialNotFound):
        await alice_oauth.token()
    with pytest.raises(CredentialNotFound):
        await get_credential(
            datasette, oauth_row.id, actor=ALICE, scopes=[SCOPE_SHEETS]
        )


@pytest.mark.asyncio
async def test_unknown_and_invisible_ids_look_the_same(
    mock_google, service_account_keys
):
    """Bob can't tell an id that doesn't exist from alice's OAuth connection
    or her unshared service account: same status, same body once the id is
    replaced."""
    datasette = await make_datasette(mock_google)
    sa = await add_sa(datasette, service_account_keys)
    oauth_row = await add_oauth(datasette, mock_google)
    routes = [
        ("rename", {"label": "x"}),
        ("rotate-key", {"key_json": raw(service_account_keys["test"])}),
        ("delete", None),
    ]
    for action, body in routes:
        seen = set()
        for credential_id in (UNKNOWN_ID, oauth_row.id, sa.id):
            response = await post(
                datasette, f"/credentials/{credential_id}/{action}", body, actor=BOB
            )
            normalized = response.text.replace(credential_id, "<id>")
            seen.add((response.status_code, normalized))
        assert len(seen) == 1, (action, seen)
        ((status, _),) = seen
        assert status == 404
    # And the broker itself.
    messages = set()
    for credential_id in (UNKNOWN_ID, oauth_row.id, sa.id):
        with pytest.raises(CredentialNotFound) as raised:
            await get_credential(
                datasette, credential_id, actor=BOB, scopes=[SCOPE_SHEETS]
            )
        messages.add(str(raised.value).replace(credential_id, "<id>"))
    assert len(messages) == 1
    # Nothing was changed along the way.
    assert (await idb(datasette).get(sa.id)).label == sa.label


@pytest.mark.asyncio
async def test_unknown_and_invisible_ids_do_the_same_permission_work(
    mock_google, service_account_keys, monkeypatch
):
    """Ticket 24: an unknown id runs the same row read and the same
    allowed()/allowed_many() calls, in the same order, as alice's OAuth
    connection or her unshared service account, so timing can't tell them
    apart either. The OAuth id itself never reaches allowed() (D19): its
    checks, like the unknown id's, run against DECOY_SA_ID."""
    datasette = await make_datasette(mock_google)
    sa = await add_sa(datasette, service_account_keys)
    oauth_row = await add_oauth(datasette, mock_google)
    key_json = raw(service_account_keys["test"])

    calls: list[tuple] = []
    current_id = None
    real_get = InternalDB.get
    real_allowed, real_allowed_many = datasette.allowed, datasette.allowed_many

    def resource(r):
        if r is None:
            return None
        assert r.parent != oauth_row.id  # D19
        # The real id or the decoy; which one is the point of the decoy.
        return (r.name, "<id>" if r.parent in {current_id, DECOY_SA_ID} else r.parent)

    async def spy_get(self, id):
        calls.append(("get", "<id>" if id == current_id else id))
        return await real_get(self, id)

    async def spy_allowed(**kwargs):
        calls.append(("allowed", kwargs["action"], resource(kwargs.get("resource"))))
        return await real_allowed(**kwargs)

    async def spy_allowed_many(**kwargs):
        calls.append(
            (
                "allowed_many",
                tuple(kwargs["actions"]),
                resource(kwargs.get("resource")),
            )
        )
        return await real_allowed_many(**kwargs)

    monkeypatch.setattr(InternalDB, "get", spy_get)
    monkeypatch.setattr(datasette, "allowed", spy_allowed)
    monkeypatch.setattr(datasette, "allowed_many", spy_allowed_many)

    operations = {
        "get_credential": lambda id: get_credential(
            datasette, id, actor=BOB, scopes=[SCOPE_SHEETS]
        ),
        "rename": lambda id: service_module.rename(datasette, BOB, id, "x"),
        "rotate-key": lambda id: service_module.rotate_service_account_key(
            datasette, BOB, id, key_json
        ),
        "delete": lambda id: service_module.delete(datasette, BOB, id),
        "reconnect": lambda id: service_module.reconnect_url(datasette, BOB, id),
    }
    for name, operation in operations.items():
        sequences = {}
        for credential_id in (UNKNOWN_ID, oauth_row.id, sa.id):
            current_id = credential_id
            calls.clear()
            with pytest.raises(CredentialNotFound):
                await operation(credential_id)
            sequences[credential_id] = list(calls)
        assert sequences[UNKNOWN_ID] == sequences[oauth_row.id], name
        assert sequences[UNKNOWN_ID] == sequences[sa.id], name
        assert any(call[0] == "allowed" for call in sequences[UNKNOWN_ID]), name
    assert (await real_get(idb(datasette), sa.id)).label == sa.label
    assert await real_get(idb(datasette), oauth_row.id) is not None


def _post_routes() -> list[str]:
    document = router.openapi_document_json()
    return sorted(
        path for path, methods in document["paths"].items() if "post" in methods
    )


@pytest.mark.asyncio
async def test_every_post_route_rejects_cross_site_requests(
    mock_google, service_account_keys
):
    datasette = await make_datasette(mock_google)
    sa = await add_sa(datasette, service_account_keys)
    routes = _post_routes()
    assert len(routes) == 4, routes  # a new POST route must be checked here
    for route in routes:
        path = re.sub(r"\{credential_id\}", sa.id, route)
        body = {"label": "pwned", "key_json": raw(service_account_keys["test"])}
        if path.endswith("/rename"):
            body = {"label": "pwned"}
        elif path.endswith("/rotate-key"):
            body = {"key_json": raw(service_account_keys["test"])}
        elif path.endswith("/delete"):
            body = None
        for headers in (
            {"Sec-Fetch-Site": "cross-site"},
            {"Origin": "https://evil.example"},
        ):
            response = await datasette.client.post(
                path, json=body, actor=ALICE, headers=headers
            )
            assert response.status_code == 403, (path, headers)
    rows = await idb(datasette).list_all()
    assert [(row.id, row.label) for row in rows] == [(sa.id, sa.label)]


@pytest.mark.parametrize(
    "value",
    [
        "//evil.com",
        "///evil.com",
        "/\\evil.com",
        "\\\\evil.com",
        "https://evil.com",
        "HTTPS://evil.com",
        "http:evil.com",
        "https:/evil.com",
        "javascript:alert(1)",
        "data:text/html,x",
        "/%2F/evil.com",
        "/%2f%2fevil.com",
        "%2F%2Fevil.com",
        "/%5Cevil.com",
        "/%5c%5cevil.com",
        "/%09/evil.com",
        "/\t/evil.com",
        "/\n/evil.com",
        "/\x00evil",
        " //evil.com",
        "evil.com",
        "@evil.com",
    ],
)
def test_return_to_rejects_off_site_targets(value):
    assert safe_return_to(value) == "/-/google-credentials"


@pytest.mark.asyncio
async def test_signed_state_with_off_site_return_to_still_lands_home(mock_google):
    """Even a validly signed state (a bug elsewhere, a leaked secret) can't
    send the callback off-site: the return_to is re-validated."""
    datasette = await make_datasette(mock_google)
    state = sign_state(
        datasette, FlowState("alice", "//evil.com", "nonce-1", int(time.time()))
    )
    cookie = datasette.sign(
        {"v": "verifier", "n": "nonce-1"}, namespace=FLOW_COOKIE_NAMESPACE
    )
    response = await datasette.client.get(
        "/-/google-credentials/oauth/callback?"
        + urlencode({"state": state, "error": "access_denied"}),
        actor=ALICE,
        cookies={FLOW_COOKIE: cookie},
    )
    assert response.status_code == 302
    assert response.headers["location"] == "/-/google-credentials"


# --- Input handling -------------------------------------------------------------

XSS = "</script><img src=x onerror=alert(1)>"


def _page_data(html: str) -> dict:
    match = re.search(
        r'<script type="application/json" id="pageData">(.*?)</script>', html, re.S
    )
    assert match
    return json.loads(match.group(1))


@pytest.mark.asyncio
async def test_labels_and_emails_are_escaped_in_every_page(
    mock_google, service_account_keys
):
    datasette = await make_datasette(mock_google)
    sa = await add_sa(datasette, service_account_keys)
    response = await post(datasette, f"/credentials/{sa.id}/rename", {"label": XSS})
    assert response.status_code == 200
    # A Google account whose email is markup, connected through the real flow.
    evil_email = "<b>bold</b>@example.com"
    mock_google.oauth.user = GoogleUser("sub-xss", evil_email)
    callback = await Connect(datasette, mock_google).connect()
    assert callback.status_code == 302

    page = await datasette.client.get(
        "/-/google-credentials", actor=ALICE, cookies=dict(callback.cookies)
    )
    assert page.status_code == 200
    assert XSS not in page.text
    assert "<img src=x" not in page.text
    assert "<b>bold</b>" not in page.text
    # The flash message ("Connected Google account ...") is escaped by core.
    assert "&lt;b&gt;bold&lt;/b&gt;@example.com" in page.text
    # #pageData round-trips the exact strings for Svelte to render as text.
    labels = {c["label"] for c in _page_data(page.text)["credentials"]}
    assert {XSS, evil_email} <= labels

    admin = await datasette.client.get("/-/google-credentials/admin", actor=ADMIN_ACTOR)
    assert admin.status_code == 200
    assert XSS not in admin.text and "<b>bold</b>" not in admin.text
    assert {XSS, evil_email} <= {
        c["label"] for c in _page_data(admin.text)["credentials"]
    }


def test_frontend_never_renders_raw_html():
    sources = [
        path
        for path in (ROOT_DIR / "frontend" / "src").rglob("*")
        if path.suffix in {".svelte", ".ts"}
    ]
    assert sources
    for path in sources:
        text = path.read_text()
        for sink in ("{@html", "innerHTML", "outerHTML", "insertAdjacentHTML"):
            assert sink not in text, (path, sink)
    for path in (PACKAGE_DIR / "templates").glob("*.html"):
        text = path.read_text()
        # The one `| safe` is datasette-vite's generated script tags.
        assert text.count("| safe") + text.count("|safe") <= 1, path
        assert "page_data | tojson" in text


def test_exporter_sample_only_writes_raw():
    source = (ROOT_DIR / "samples" / "google_sheets_export.py").read_text()
    options = re.findall(r'"valueInputOption":\s*"(\w+)"', source)
    assert options and set(options) == {"RAW"}
    assert "USER_ENTERED" not in source


# --- Operational ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_removing_or_changing_the_key_fails_clearly(
    mock_google, service_account_keys, tmp_path
):
    internal = str(tmp_path / "internal.db")
    first = await make_datasette(mock_google, internal=internal)
    sa = await add_sa(first, service_account_keys)
    oauth_row = await add_oauth(first, mock_google)
    first.close()

    # No key at all: startup is fine, listing works, use says why it can't.
    no_key = mock_google.datasette(
        plugin_config={},
        config={"permissions": {ADMIN: {"id": "admin"}}},
        internal=internal,
    )
    await no_key.invoke_startup()
    status = (await no_key.client.get(f"{API}/status", actor=ALICE)).json()
    assert status["encryption_configured"] is False
    listing = (await no_key.client.get(f"{API}/credentials", actor=ALICE)).json()
    assert {c["id"] for c in listing["credentials"]} == {sa.id, oauth_row.id}
    assert (
        await no_key.client.get("/-/google-credentials", actor=ALICE)
    ).status_code == 200
    for credential_id in (sa.id, oauth_row.id):
        cred = await get_credential(
            no_key, credential_id, actor=ALICE, scopes=[SCOPE_SHEETS]
        )
        with pytest.raises(EncryptionNotConfigured) as raised:
            await cred.request("GET", STUDENTS)
        assert error_response(raised.value).status == 503
    # Deleting still works (the OAuth revoke is skipped and reported).
    deleted = await post(no_key, f"/credentials/{oauth_row.id}/delete")
    assert deleted.status_code == 200
    assert deleted.json()["revoked"] is False
    no_key.close()

    # A different key: startup is fine, use fails with "was the key changed?",
    # and the row isn't marked broken.
    other_key = await make_datasette(mock_google, internal=internal)
    cred = await get_credential(other_key, sa.id, actor=ALICE, scopes=[SCOPE_SHEETS])
    with pytest.raises(CredentialUndecryptable) as raised:
        await cred.token()
    assert "encryption-key" in str(raised.value)
    assert error_response(raised.value).status == 500
    assert (await idb(other_key).get(sa.id)).status == "ok"
    other_key.close()
