"""
Two-way conformance between `datasette_google_auth/telemetry_registry.py`
and what the plugin actually emits, plus the privacy walk (D29).

`just telemetry-doc-check` guarantees the README matches the registry; this
guarantees the registry matches the code, in both directions: emitted but
not registered (undocumented instrumentation) and registered but never
emitted (documentation of a signal that no longer exists). Neither catches a
rename, because call sites take their names from the registry, so the
literal names are spelled out here too.

The privacy walk plants sentinels (actor id, label, Google identity, a
spreadsheet id and query value in a request URL), harvests every secret the
mock saw or issued, and asserts none of them reaches any signal, core's
included. It drives the broker directly and the JSON API routes and pages
through ``datasette.client``, so core's request span is covered too.
"""

import json
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit

import httpx2
import pytest

pytest.importorskip("opentelemetry.sdk")

from cryptography.fernet import Fernet  # noqa: E402
from datasette.telemetry_testing import (  # noqa: E402
    assert_metrics_conform,
    assert_metrics_covered,
    assert_no_forbidden_values,
    assert_package_never_imports_sdk,
    assert_spans_conform,
    assert_spans_covered,
)
from mock_google import SHEETS_BASE  # noqa: E402
from mock_google.oauth import (  # noqa: E402
    DEFAULT_REDIRECT_URI,
    MSG_REVOKED,
    OAUTH_CLIENT_SECRET,
    SCOPE_EMAIL,
    SCOPE_OPENID,
    SCOPE_SHEETS,
    GoogleUser,
)
from mock_google.tokens import MSG_UNKNOWN_ACCOUNT  # noqa: E402

from datasette_google_auth import get_credential  # noqa: E402
from datasette_google_auth import telemetry_registry as reg  # noqa: E402
from datasette_google_auth.crypto import (  # noqa: E402
    decrypt_credential,
    encrypt_secret,
)
from datasette_google_auth.errors import (  # noqa: E402
    CredentialBroken,
    CredentialNotFound,
    DisallowedHost,
    GoogleTokenError,
    InvalidServiceAccountKey,
)
from datasette_google_auth.http import set_transport  # noqa: E402
from datasette_google_auth.internal_db import InternalDB  # noqa: E402
from datasette_google_auth.oauth import FLOW_COOKIE  # noqa: E402
from datasette_google_auth.permissions import (  # noqa: E402
    ADD_SERVICE_ACCOUNT,
    CONNECT,
    seed_manager,
)
from datasette_google_auth.service import (  # noqa: E402
    add_service_account,
    delete,
    rotate_service_account_key,
)
from datasette_google_auth.service_account import parse_key  # noqa: E402
from datasette_google_auth.token_cache import get_token_cache  # noqa: E402

SCOPE = "datasette_google_auth"

ACTOR_ID = "actor-sentinel-XYZZY"
ACTOR = {"id": ACTOR_ID}
LABEL = "label-sentinel-XYZZY"
USER = GoogleUser("sub-sentinel-XYZZY", "email-sentinel-XYZZY@example.com")
SHEET_ID = "sheet-sentinel-XYZZY"
QUERY_VALUE = "query-sentinel-XYZZY"
ALL_SCOPES = [SCOPE_OPENID, SCOPE_EMAIL, SCOPE_SHEETS]
STUDENTS = f"{SHEETS_BASE}/v4/spreadsheets/students"
API = "/-/google-auth/api"

# Form fields that carry a secret or identifier (grant_type, redirect_uri
# and scope are public constants).
SECRET_FORM_FIELDS = {
    "code",
    "code_verifier",
    "refresh_token",
    "assertion",
    "token",
    "client_id",
    "client_secret",
}


def test_package_never_imports_the_sdk():
    # Front-loaded by conftest's pytest_collection_modifyitems.
    assert_package_never_imports_sdk("datasette_google_auth")


# The names as they appear on the wire, written out rather than read from the
# registry. If a registry change fails this, it renames something dashboards
# depend on: a decision to take deliberately, here.
EXPECTED_ATTRIBUTES = {
    "datasette_google_auth.token": {
        "datasette_google_auth.credential.id",
        "datasette_google_auth.credential.type",
        "datasette_google_auth.cache",
        "error.type",
    },
    "datasette_google_auth.request": {
        "datasette_google_auth.credential.id",
        "datasette_google_auth.credential.type",
        "http.request.method",
        "server.address",
        "http.response.status_code",
        "datasette_google_auth.retried",
        "error.type",
    },
    "datasette_google_auth.token.mint": {
        "datasette_google_auth.scopes.count",
        "datasette_google_auth.outcome",
        "http.response.status_code",
        "datasette_google_auth.google.error",
        "error.type",
    },
    "datasette_google_auth.token.refresh": {
        "datasette_google_auth.outcome",
        "http.response.status_code",
        "datasette_google_auth.google.error",
        "datasette_google_auth.refresh_token.rotated",
        "error.type",
    },
    "datasette_google_auth.oauth.exchange": {
        "datasette_google_auth.outcome",
        "http.response.status_code",
        "datasette_google_auth.google.error",
        "error.type",
    },
    "datasette_google_auth.oauth.userinfo": {
        "datasette_google_auth.outcome",
        "http.response.status_code",
        "datasette_google_auth.google.error",
        "error.type",
    },
    "datasette_google_auth.oauth.revoke": {
        "datasette_google_auth.outcome",
        "http.response.status_code",
        "datasette_google_auth.google.error",
        "error.type",
    },
    "datasette_google_auth.oauth.callback": {
        "datasette_google_auth.callback.result",
        "datasette_google_auth.credential.id",
        "datasette_google_auth.google.error",
        "datasette_google_auth.scopes.missing",
        "error.type",
    },
}

EXPECTED_METRIC_ATTRIBUTES = {
    "datasette_google_auth.google.duration": {
        "datasette_google_auth.google.operation",
        "datasette_google_auth.outcome",
        "datasette_google_auth.google.error",
    },
    "datasette_google_auth.token_cache.lookups": {
        "datasette_google_auth.credential.type",
        "datasette_google_auth.cache",
    },
    "datasette_google_auth.request.duration": {
        "datasette_google_auth.credential.type",
        "http.request.method",
        "http.response.status_code",
        "datasette_google_auth.retried",
        "error.type",
    },
    "datasette_google_auth.credentials.broken": {
        "datasette_google_auth.credential.type",
    },
    "datasette_google_auth.oauth.callbacks": {
        "datasette_google_auth.callback.result",
    },
}


def test_registry_matches_expected_literal_names():
    assert {str(s) for s in reg.SPANS} == set(EXPECTED_ATTRIBUTES)
    for span in reg.SPANS:
        assert {str(a) for a in span.attributes} == EXPECTED_ATTRIBUTES[str(span)], str(
            span
        )
    assert {str(m) for m in reg.METRICS} == set(EXPECTED_METRIC_ATTRIBUTES)
    for metric in reg.METRICS:
        assert {str(a) for a in metric.attributes} == EXPECTED_METRIC_ATTRIBUTES[
            str(metric)
        ], str(metric)


def test_no_metric_dimension_is_an_identifier():
    # D29: credential ids on spans only. Every metric attribute is a closed
    # enum, a bool, a clamped method, a status code or a class name.
    for metric in reg.METRICS:
        assert "datasette_google_auth.credential.id" not in metric.attributes


def test_histograms_declare_buckets():
    for metric in reg.METRICS:
        if metric.kind == reg.HISTOGRAM:
            assert metric.buckets == reg.GOOGLE_DURATION_BUCKETS, str(metric)


# --- The workload ---------------------------------------------------------------


async def make_datasette(mock_google):
    datasette = mock_google.datasette(
        plugin_config={"encryption-key": Fernet.generate_key().decode()},
        config={
            "permissions": {
                CONNECT: {"id": ACTOR_ID},
                ADD_SERVICE_ACCOUNT: {"id": ACTOR_ID},
            }
        },
    )
    await datasette.invoke_startup()
    return datasette


def idb(datasette) -> InternalDB:
    return InternalDB(datasette.get_internal_database())


async def oauth_rows(datasette):
    return [
        row
        for row in await idb(datasette).list_owned(ACTOR_ID)
        if row.type == "google_oauth"
    ]


def raw(key) -> str:
    return json.dumps(key.key_json())


def path_and_query(url: str) -> str:
    parts = urlsplit(url)
    return parts.path + ("?" + parts.query if parts.query else "")


class Flow:
    """Connect Google against the mock, remembering every state and cookie."""

    def __init__(self, datasette, mock_google):
        self.datasette = datasette
        self.mock_google = mock_google
        self.secrets: set[str] = set()

    async def authorize(self):
        response = await self.datasette.client.get(
            "/-/google-auth/connect?" + urlencode({"return_to": "/"}), actor=ACTOR
        )
        assert response.status_code == 302
        cookie = response.cookies[FLOW_COOKIE]
        location = response.headers["location"]
        state = parse_qs(urlsplit(location).query)["state"][0]
        self.secrets |= {cookie, state}
        async with self.mock_google.client() as google:
            consent = await google.get(location)
        callback_url = consent.headers["location"]
        assert callback_url.startswith(DEFAULT_REDIRECT_URI)
        return callback_url, cookie

    async def callback(self, callback_url, cookie):
        return await self.datasette.client.get(
            path_and_query(callback_url), actor=ACTOR, cookies={FLOW_COOKIE: cookie}
        )

    async def connect(self):
        return await self.callback(*await self.authorize())


def refuse(request):
    raise httpx2.ConnectError("refused", request=request)


async def run_workload(datasette, mock_google, service_account_keys):
    """Every signal, happy and failure paths. Returns flow secrets seen."""
    mock_google.oauth.user = USER
    mock_google.oauth.rotate_refresh_tokens = True
    flow = Flow(datasette, mock_google)

    # Service account: live-test mint, token miss then hit, requests.
    info = await add_service_account(
        datasette, ACTOR, raw(service_account_keys["test"]), LABEL
    )
    sa = await get_credential(datasette, info.id, actor=ACTOR, scopes=[SCOPE_SHEETS])
    await sa.token()
    await sa.token()
    response = await sa.request(
        "GET", f"{SHEETS_BASE}/v4/spreadsheets/{SHEET_ID}?q={QUERY_VALUE}"
    )
    assert response.status_code == 404
    mock_google.faults.fail("/v4/spreadsheets/", 401, times=1)
    assert (await sa.request("GET", STUDENTS)).status_code == 200

    # Token endpoint 500, then a network error.
    get_token_cache(datasette).evict(info.id)
    mock_google.faults.fail("/token", 500)
    with pytest.raises(GoogleTokenError):
        await sa.token()
    set_transport(datasette, httpx2.MockTransport(refuse))
    with pytest.raises(GoogleTokenError):
        await sa.request("GET", STUDENTS)
    mock_google.attach(datasette)

    # A deleted key: invalid_grant, marked broken.
    key = parse_key(raw(service_account_keys["unregistered"]))
    row = await idb(datasette).insert(
        type="service_account",
        label=LABEL,
        owner_id=ACTOR_ID,
        created_by=ACTOR_ID,
        secret_encrypted=encrypt_secret(datasette, key.to_secret()),
        google_subject=key.client_id,
        google_email=key.client_email,
    )
    await seed_manager(datasette, row.id, ACTOR_ID)
    broken = await get_credential(datasette, row.id, actor=ACTOR, scopes=[SCOPE_SHEETS])
    with pytest.raises(CredentialBroken):
        await broken.token()

    # Rotating in a key for another account is refused (its message names
    # the stored client_email).
    with pytest.raises(InvalidServiceAccountKey):
        await rotate_service_account_key(
            datasette, ACTOR, info.id, raw(service_account_keys["other"])
        )

    # A URL outside the allowlist (D34), with sentinels in userinfo, path
    # and query: refused before any token fetch, host only on the span.
    with pytest.raises(DisallowedHost):
        await sa.request(
            "GET", f"https://{ACTOR_ID}@evil.example.com/{SHEET_ID}?q={QUERY_VALUE}"
        )

    # The JSON API and pages, each inside core's request span: no
    # GoogleAuthError may escape a route and put its message there (D29).
    for path in (
        f"{API}/status",
        f"{API}/credentials",
        f"{API}/credentials?scopes={SCOPE_SHEETS}",
        f"{API}/admin/credentials",  # 403: not an admin
        "/-/google-auth",
        "/-/google-auth/admin",
    ):
        await datasette.client.get(path, actor=ACTOR)
    added = await datasette.client.post(
        f"{API}/service-accounts",
        json={"label": LABEL, "key_json": raw(service_account_keys["other"])},
        actor=ACTOR,
    )
    assert added.status_code == 200
    other_id = added.json()["id"]
    renamed = await datasette.client.post(
        f"{API}/credentials/{other_id}/rename", json={"label": LABEL}, actor=ACTOR
    )
    assert renamed.status_code == 200
    # Its message names the stored client_email (key material to the walk).
    wrong_key = await datasette.client.post(
        f"{API}/credentials/{other_id}/rotate-key",
        json={"key_json": raw(service_account_keys["test"])},
        actor=ACTOR,
    )
    assert wrong_key.status_code == 400
    unknown = await datasette.client.post(
        f"{API}/credentials/no-such-id/delete", actor=ACTOR
    )
    assert unknown.status_code == 404
    deleted = await datasette.client.post(
        f"{API}/credentials/{other_id}/delete", actor=ACTOR
    )
    assert deleted.status_code == 200

    # Connect Google: created, reconnected, then refresh (rotated).
    assert (await flow.connect()).status_code == 302
    assert (await flow.connect()).status_code == 302
    (oauth_row,) = await oauth_rows(datasette)
    oauth = await get_credential(
        datasette, oauth_row.id, actor=ACTOR, scopes=[SCOPE_SHEETS]
    )
    get_token_cache(datasette).evict(oauth_row.id)
    await oauth.token()

    # Callback failures: cancelled, tampered state, reused code.
    mock_google.oauth.deny = True
    await flow.connect()
    mock_google.oauth.deny = False
    callback_url, cookie = await flow.authorize()
    parts = urlsplit(callback_url)
    params = {k: v[-1] for k, v in parse_qs(parts.query).items()}
    tampered = dict(params, state=params["state"][:-4] + "AAAA")
    await flow.callback(urlunsplit(parts._replace(query=urlencode(tampered))), cookie)
    assert (await flow.callback(callback_url, cookie)).status_code == 302
    assert (await flow.callback(callback_url, cookie)).status_code == 400

    # Refresh invalid_grant: the grant is revoked at Google.
    oauth_row = await idb(datasette).get(oauth_row.id)
    assert oauth_row is not None
    refresh_token = (await decrypt_credential(datasette, oauth_row))["refresh_token"]
    async with mock_google.client() as google:
        await google.post("/revoke", data={"token": refresh_token})
    get_token_cache(datasette).evict(oauth_row.id)
    with pytest.raises(CredentialBroken):
        await oauth.token()

    # Revoke on delete: ok, then a 500 (a second grant for a new account).
    await delete(datasette, ACTOR, oauth_row.id)
    mock_google.oauth.user = GoogleUser("sub-sentinel-2-XYZZY", "second@example.com")
    await flow.connect()
    (second,) = await oauth_rows(datasette)
    mock_google.faults.fail("/revoke", 500)
    await delete(datasette, ACTOR, second.id)

    # An access decision on a held credential.
    with pytest.raises(CredentialNotFound):
        await oauth.token()
    return flow.secrets


def harvested_secrets(mock_google) -> set[str]:
    found = set(mock_google.tokens.issued_tokens())
    found |= set(mock_google.oauth.refresh_tokens())
    for request in mock_google.requests:
        for name, value in (request.form or {}).items():
            if name in SECRET_FORM_FIELDS:
                found.add(value)
        authorization = request.headers.get("authorization")
        if authorization:
            found.add(authorization)
            found.add(authorization.partition(" ")[2])
    return found


def key_material(service_account_keys) -> set[str]:
    found = set()
    for key in service_account_keys.values():
        pem = key.private_key_pem
        body = "".join(line for line in pem.splitlines() if "-----" not in line)
        found |= {
            pem,
            body[100:140],
            key.private_key_id,
            key.client_id,
            key.client_email,
            key.project_id,
        }
    return found


@pytest.mark.asyncio
async def test_registry_conformance_and_privacy(
    mock_google, service_account_keys, otel_spans, otel_metrics
):
    datasette = await make_datasette(mock_google)
    flow_secrets = await run_workload(datasette, mock_google, service_account_keys)
    otel_metrics.collect()
    finished = otel_spans.get_finished_spans()

    assert_spans_conform(reg.SPANS, finished, scope_name=SCOPE)
    assert_spans_covered(reg.SPANS, finished, scope_name=SCOPE)
    assert_metrics_conform(reg.METRICS, otel_metrics, scope_name=SCOPE)
    assert_metrics_covered(reg.METRICS, otel_metrics, scope_name=SCOPE)

    # Every internal-DB write/read uses a named callback, never a lambda.
    lambdas = [
        span
        for span in finished
        if (span.attributes or {}).get("datasette.callback") == "<lambda>"
    ]
    assert lambdas == []

    harvested = harvested_secrets(mock_google)
    # Sanity: the harvest really found the secrets the workload used.
    assert any(value.startswith("ya29.mock-") for value in harvested)
    assert any(value.startswith("1//mock-") for value in harvested)
    assert any(value.startswith("4/mock-") for value in harvested)

    forbidden = (
        {ACTOR_ID, LABEL, USER.sub, USER.email, SHEET_ID, QUERY_VALUE}
        | key_material(service_account_keys)
        | {OAUTH_CLIENT_SECRET}
        | harvested
        | flow_secrets
        | {MSG_UNKNOWN_ACCOUNT, MSG_REVOKED, "mock_google: injected fault"}
    )
    # scope_name unset: a leak through core's signals is still a leak.
    assert_no_forbidden_values(
        forbidden, finished_spans=finished, collector=otel_metrics
    )
