"""One test per signal: the spans and metrics in telemetry_registry, driven
through the mock Google. Registry conformance and the privacy walk live in
test_telemetry_registry.py."""

import json
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit

import httpx2
import pytest

pytest.importorskip("opentelemetry.sdk")

from cryptography.fernet import Fernet  # noqa: E402
from datasette.telemetry import SCHEMA_URL  # noqa: E402
from mock_google import MOCK_BASE, SHEETS_BASE  # noqa: E402
from mock_google.oauth import (  # noqa: E402
    DEFAULT_REDIRECT_URI,
    SCOPE_EMAIL,
    SCOPE_OPENID,
    SCOPE_SHEETS,
)
from opentelemetry.trace import SpanKind, StatusCode  # noqa: E402

from datasette_google_credentials import get_credential  # noqa: E402
from datasette_google_credentials.crypto import (  # noqa: E402
    decrypt_credential,
    encrypt_secret,
)
from datasette_google_credentials.errors import (  # noqa: E402
    CredentialBroken,
    CredentialNotFound,
    GoogleTokenError,
)
from datasette_google_credentials.internal_db import InternalDB  # noqa: E402
from datasette_google_credentials.oauth import FLOW_COOKIE  # noqa: E402
from datasette_google_credentials.permissions import (  # noqa: E402
    ADD_SERVICE_ACCOUNT,
    ADMIN,
    CONNECT,
    seed_manager,
)
from datasette_google_credentials.service import (  # noqa: E402
    add_service_account,
    delete,
)
from datasette_google_credentials.service_account import (  # noqa: E402
    mint_token,
    parse_key,
)
from datasette_google_credentials.telemetry import clamp_google_error  # noqa: E402

P = "datasette_google_credentials."
SCOPE = "datasette_google_credentials"
ALICE = {"id": "alice"}
ALL_SCOPES = [SCOPE_OPENID, SCOPE_EMAIL, SCOPE_SHEETS]
STUDENTS = f"{SHEETS_BASE}/v4/spreadsheets/students"


# --- Helpers (local copies of test_lifecycle / test_oauth ones) ---------------


async def make_datasette(mock_google, **plugin_config):
    datasette = mock_google.datasette(
        plugin_config={"encryption-key": Fernet.generate_key().decode()}
        | plugin_config,
        config={
            "permissions": {
                CONNECT: {"id": ["alice", "bob"]},
                ADD_SERVICE_ACCOUNT: {"id": "alice"},
                ADMIN: {"id": "admin"},
            }
        },
    )
    await datasette.invoke_startup()
    return datasette


def idb(datasette) -> InternalDB:
    return InternalDB(datasette.get_internal_database())


async def add_sa(datasette, service_account_keys, name="test"):
    return await add_service_account(
        datasette, ALICE, json.dumps(service_account_keys[name].key_json()), ""
    )


async def add_unregistered_sa(datasette, service_account_keys):
    """A service account whose key Google no longer accepts."""
    key = parse_key(json.dumps(service_account_keys["unregistered"].key_json()))
    row = await idb(datasette).insert(
        type="service_account",
        label="deleted key",
        owner_id="alice",
        created_by="alice",
        secret_encrypted=encrypt_secret(datasette, key.to_secret()),
        google_subject=key.client_id,
        google_email=key.client_email,
    )
    await seed_manager(datasette, row.id, "alice")
    return row


async def add_oauth(datasette, mock_google, owner="alice"):
    refresh_token = mock_google.oauth.issue_refresh_token(scopes=frozenset(ALL_SCOPES))
    row, _ = await idb(datasette).upsert_oauth(
        owner,
        "sub-1",
        google_email="user@example.com",
        label="user@example.com",
        scopes=ALL_SCOPES,
        secret_encrypted=encrypt_secret(datasette, {"refresh_token": refresh_token}),
        actor_id=owner,
    )
    return row


def path_and_query(url: str) -> str:
    parts = urlsplit(url)
    return parts.path + ("?" + parts.query if parts.query else "")


async def start(datasette, actor=ALICE):
    response = await datasette.client.get(
        "/-/google-credentials/connect?" + urlencode({"return_to": "/"}), actor=actor
    )
    assert response.status_code == 302
    return response.headers["location"], response.cookies[FLOW_COOKIE]


async def consent(mock_google, authorize_url):
    async with mock_google.client() as google:
        response = await google.get(authorize_url)
    assert response.status_code == 302, response.text
    location = response.headers["location"]
    assert location.startswith(DEFAULT_REDIRECT_URI)
    return location


async def callback(datasette, callback_url, cookie, actor=ALICE):
    return await datasette.client.get(
        path_and_query(callback_url), actor=actor, cookies={FLOW_COOKIE: cookie}
    )


async def connect(datasette, mock_google, actor=ALICE):
    authorize_url, cookie = await start(datasette, actor)
    callback_url = await consent(mock_google, authorize_url)
    return await callback(datasette, callback_url, cookie, actor)


def ours(otel_spans, name=None):
    return [
        span
        for span in otel_spans.get_finished_spans()
        if span.instrumentation_scope.name == SCOPE
        and (name is None or span.name == P + name)
    ]


def one(otel_spans, name):
    (span,) = ours(otel_spans, name)
    return span


def children(otel_spans, parent, name=None):
    return [
        span
        for span in ours(otel_spans, name)
        if span.parent is not None and span.parent.span_id == parent.context.span_id
    ]


def attrs(span) -> dict:
    return dict(span.attributes or {})


def assert_error(span):
    assert span.status.status_code == StatusCode.ERROR
    assert not span.status.description


# --- Scope --------------------------------------------------------------------


@pytest.mark.asyncio
async def test_scope_and_schema(mock_google, service_account_keys, otel_spans):
    datasette = await make_datasette(mock_google)
    await add_sa(datasette, service_account_keys)
    span = one(otel_spans, "token.mint")
    assert span.instrumentation_scope.name == SCOPE
    assert span.instrumentation_scope.schema_url == SCHEMA_URL
    assert span.instrumentation_scope.version


# --- token --------------------------------------------------------------------


@pytest.mark.asyncio
async def test_token_miss_then_hit(
    mock_google, service_account_keys, otel_spans, otel_metrics
):
    datasette = await make_datasette(mock_google)
    info = await add_sa(datasette, service_account_keys)
    cred = await get_credential(datasette, info.id, actor=ALICE, scopes=[SCOPE_SHEETS])
    otel_spans.clear()
    otel_metrics.collect()  # drain the live test's measurements

    await cred.token()
    await cred.token()

    first, second = ours(otel_spans, "token")
    for span in (first, second):
        assert span.kind == SpanKind.INTERNAL
        assert attrs(span)[P + "credential.id"] == info.id
        assert attrs(span)[P + "credential.type"] == "service_account"
        assert span.status.status_code == StatusCode.UNSET
    assert attrs(first)[P + "cache"] == "miss"
    assert [s.name for s in children(otel_spans, first)] == [P + "token.mint"]
    assert attrs(second)[P + "cache"] == "hit"
    assert children(otel_spans, second) == []

    otel_metrics.collect()
    lookups = P + "token_cache.lookups"
    base = {P + "credential.type": "service_account"}
    assert otel_metrics.point(lookups, base | {P + "cache": "hit"}).value == 1
    assert otel_metrics.point(lookups, base | {P + "cache": "miss"}).value == 1


@pytest.mark.asyncio
async def test_token_not_found_is_an_outcome_not_an_error(
    mock_google, service_account_keys, otel_spans
):
    datasette = await make_datasette(mock_google)
    info = await add_sa(datasette, service_account_keys)
    cred = await get_credential(datasette, info.id, actor=ALICE, scopes=[SCOPE_SHEETS])
    await idb(datasette).delete(info.id)
    with pytest.raises(CredentialNotFound):
        await cred.token()
    span = one(otel_spans, "token")
    assert attrs(span)["error.type"] == "CredentialNotFound"
    assert P + "credential.type" not in attrs(span)
    assert span.status.status_code == StatusCode.UNSET


# --- token.mint ----------------------------------------------------------------


@pytest.mark.asyncio
async def test_mint_ok(mock_google, service_account_keys, otel_spans, otel_metrics):
    datasette = await make_datasette(mock_google)
    await add_sa(datasette, service_account_keys)
    span = one(otel_spans, "token.mint")
    assert span.kind == SpanKind.CLIENT
    assert attrs(span) == {
        P + "scopes.count": 1,
        P + "outcome": "ok",
        "http.response.status_code": 200,
    }
    assert span.status.status_code == StatusCode.UNSET
    otel_metrics.collect()
    point = otel_metrics.point(
        P + "google.duration",
        {P + "google.operation": "mint", P + "outcome": "ok"},
    )
    assert point.count == 1


@pytest.mark.asyncio
async def test_mint_invalid_grant_breaks_the_credential(
    mock_google, service_account_keys, otel_spans, otel_metrics
):
    datasette = await make_datasette(mock_google)
    row = await add_unregistered_sa(datasette, service_account_keys)
    cred = await get_credential(datasette, row.id, actor=ALICE, scopes=[SCOPE_SHEETS])
    with pytest.raises(CredentialBroken):
        await cred.token()

    mint = one(otel_spans, "token.mint")
    assert attrs(mint)[P + "outcome"] == "invalid_grant"
    assert attrs(mint)[P + "google.error"] == "invalid_grant"
    assert attrs(mint)["http.response.status_code"] == 400
    assert attrs(mint)["error.type"] == "CredentialBroken"
    assert_error(mint)
    token = one(otel_spans, "token")
    assert attrs(token)["error.type"] == "CredentialBroken"
    assert_error(token)

    otel_metrics.collect()
    broken = otel_metrics.point(
        P + "credentials.broken", {P + "credential.type": "service_account"}
    )
    assert broken.value == 1
    assert otel_metrics.point(
        P + "google.duration",
        {P + "google.operation": "mint", P + "outcome": "invalid_grant"},
    )


@pytest.mark.asyncio
async def test_mint_http_error(mock_google, service_account_keys, otel_spans):
    datasette = await make_datasette(mock_google)
    info = await add_sa(datasette, service_account_keys)
    cred = await get_credential(datasette, info.id, actor=ALICE, scopes=[SCOPE_SHEETS])
    otel_spans.clear()
    mock_google.faults.fail("/token", 500)
    with pytest.raises(GoogleTokenError):
        await cred.token()
    mint = one(otel_spans, "token.mint")
    assert attrs(mint)[P + "outcome"] == "http_error"
    assert attrs(mint)["http.response.status_code"] == 500
    # The mock's injected `internal_failure` isn't a known OAuth code.
    assert attrs(mint)[P + "google.error"] == "_OTHER"
    assert attrs(mint)["error.type"] == "GoogleTokenError"
    assert_error(mint)


@pytest.mark.asyncio
async def test_mint_network_error(service_account_keys, otel_spans):
    def refuse(request):
        raise httpx2.ConnectError("refused", request=request)

    key = parse_key(json.dumps(service_account_keys["test"].key_json()))
    async with httpx2.AsyncClient(transport=httpx2.MockTransport(refuse)) as http:
        with pytest.raises(GoogleTokenError):
            await mint_token(http, key, [SCOPE_SHEETS], token_url=f"{MOCK_BASE}/token")
    mint = one(otel_spans, "token.mint")
    assert attrs(mint)[P + "outcome"] == "network_error"
    assert "http.response.status_code" not in attrs(mint)
    assert P + "google.error" not in attrs(mint)
    assert_error(mint)


# --- token.refresh ---------------------------------------------------------------


@pytest.mark.asyncio
async def test_refresh_ok_with_rotation(mock_google, otel_spans, otel_metrics):
    mock_google.oauth.rotate_refresh_tokens = True
    datasette = await make_datasette(mock_google)
    row = await add_oauth(datasette, mock_google)
    cred = await get_credential(datasette, row.id, actor=ALICE, scopes=[SCOPE_SHEETS])
    await cred.token()
    refresh = one(otel_spans, "token.refresh")
    assert refresh.kind == SpanKind.CLIENT
    assert attrs(refresh) == {
        P + "outcome": "ok",
        "http.response.status_code": 200,
        P + "refresh_token.rotated": True,
    }
    token = one(otel_spans, "token")
    assert attrs(token)[P + "credential.type"] == "google_oauth"
    assert refresh.parent.span_id == token.context.span_id
    otel_metrics.collect()
    assert otel_metrics.point(
        P + "google.duration",
        {P + "google.operation": "refresh", P + "outcome": "ok"},
    )


@pytest.mark.asyncio
async def test_refresh_not_rotated(mock_google, otel_spans):
    datasette = await make_datasette(mock_google)
    row = await add_oauth(datasette, mock_google)
    cred = await get_credential(datasette, row.id, actor=ALICE, scopes=[SCOPE_SHEETS])
    await cred.token()
    assert attrs(one(otel_spans, "token.refresh"))[P + "refresh_token.rotated"] is False


@pytest.mark.asyncio
async def test_refresh_invalid_grant(mock_google, otel_spans, otel_metrics):
    datasette = await make_datasette(mock_google)
    row = await add_oauth(datasette, mock_google)
    refresh_token = (await decrypt_credential(datasette, row))["refresh_token"]
    async with mock_google.client() as google:
        await google.post("/revoke", data={"token": refresh_token})
    cred = await get_credential(datasette, row.id, actor=ALICE, scopes=[SCOPE_SHEETS])
    with pytest.raises(CredentialBroken):
        await cred.token()
    refresh = one(otel_spans, "token.refresh")
    assert attrs(refresh)[P + "outcome"] == "invalid_grant"
    assert attrs(refresh)[P + "google.error"] == "invalid_grant"
    assert P + "refresh_token.rotated" not in attrs(refresh)
    assert_error(refresh)
    otel_metrics.collect()
    broken = otel_metrics.point(
        P + "credentials.broken", {P + "credential.type": "google_oauth"}
    )
    assert broken.value == 1


# --- oauth.callback ----------------------------------------------------------------


def callback_count(otel_metrics, result):
    return otel_metrics.point(
        P + "oauth.callbacks", {P + "callback.result": result}
    ).value


@pytest.mark.asyncio
async def test_callback_created_then_reconnected(mock_google, otel_spans, otel_metrics):
    datasette = await make_datasette(mock_google)
    assert (await connect(datasette, mock_google)).status_code == 302
    assert (await connect(datasette, mock_google)).status_code == 302
    (row,) = await idb(datasette).list_owned("alice")

    first, second = ours(otel_spans, "oauth.callback")
    assert attrs(first) == {
        P + "callback.result": "created",
        P + "credential.id": row.id,
        P + "scopes.missing": 0,
    }
    assert attrs(second)[P + "callback.result"] == "reconnected"
    assert attrs(second)[P + "credential.id"] == row.id
    for span in (first, second):
        assert span.status.status_code == StatusCode.UNSET
        assert sorted(s.name for s in children(otel_spans, span)) == [
            P + "oauth.exchange",
            P + "oauth.userinfo",
        ]
    for name in ("oauth.exchange", "oauth.userinfo"):
        for span in ours(otel_spans, name):
            assert span.kind == SpanKind.CLIENT
            assert attrs(span) == {
                P + "outcome": "ok",
                "http.response.status_code": 200,
            }
    otel_metrics.collect()
    assert callback_count(otel_metrics, "created") == 1
    assert callback_count(otel_metrics, "reconnected") == 1


@pytest.mark.asyncio
async def test_callback_cancelled(mock_google, otel_spans, otel_metrics):
    mock_google.oauth.deny = True
    datasette = await make_datasette(mock_google)
    await connect(datasette, mock_google)
    span = one(otel_spans, "oauth.callback")
    assert attrs(span) == {
        P + "callback.result": "cancelled",
        P + "google.error": "access_denied",
    }
    assert span.status.status_code == StatusCode.UNSET
    otel_metrics.collect()
    assert callback_count(otel_metrics, "cancelled") == 1


@pytest.mark.asyncio
async def test_callback_invalid_state(mock_google, otel_spans, otel_metrics):
    datasette = await make_datasette(mock_google)
    authorize_url, cookie = await start(datasette)
    callback_url = await consent(mock_google, authorize_url)
    parts = urlsplit(callback_url)
    params = {k: v[-1] for k, v in parse_qs(parts.query).items()}
    params["state"] = params["state"][:-4] + "AAAA"
    tampered = urlunsplit(parts._replace(query=urlencode(params)))
    response = await callback(datasette, tampered, cookie)
    assert response.status_code == 400
    span = one(otel_spans, "oauth.callback")
    assert attrs(span) == {P + "callback.result": "invalid_state"}
    assert span.status.status_code == StatusCode.UNSET
    assert children(otel_spans, span) == []
    otel_metrics.collect()
    assert callback_count(otel_metrics, "invalid_state") == 1


@pytest.mark.asyncio
async def test_callback_partial_consent(mock_google, otel_spans):
    mock_google.oauth.granted_scopes = {SCOPE_OPENID, SCOPE_EMAIL}
    datasette = await make_datasette(mock_google)
    await connect(datasette, mock_google)
    span = one(otel_spans, "oauth.callback")
    assert attrs(span)[P + "callback.result"] == "created"
    assert attrs(span)[P + "scopes.missing"] == 1


@pytest.mark.asyncio
async def test_callback_code_reuse(mock_google, otel_spans, otel_metrics):
    datasette = await make_datasette(mock_google)
    authorize_url, cookie = await start(datasette)
    callback_url = await consent(mock_google, authorize_url)
    assert (await callback(datasette, callback_url, cookie)).status_code == 302
    otel_spans.clear()
    assert (await callback(datasette, callback_url, cookie)).status_code == 400

    span = one(otel_spans, "oauth.callback")
    assert attrs(span) == {P + "callback.result": "invalid_grant"}
    assert_error(span)
    exchange = one(otel_spans, "oauth.exchange")
    assert attrs(exchange)[P + "outcome"] == "invalid_grant"
    assert attrs(exchange)["error.type"] == "CredentialBroken"
    assert_error(exchange)
    otel_metrics.collect()
    assert callback_count(otel_metrics, "invalid_grant") == 1


# --- oauth.revoke ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_revoke_ok(mock_google, otel_spans, otel_metrics):
    datasette = await make_datasette(mock_google)
    row = await add_oauth(datasette, mock_google)
    result = await delete(datasette, ALICE, row.id)
    assert result.revoked
    span = one(otel_spans, "oauth.revoke")
    assert span.kind == SpanKind.CLIENT
    assert attrs(span) == {P + "outcome": "ok", "http.response.status_code": 200}
    otel_metrics.collect()
    assert otel_metrics.point(
        P + "google.duration",
        {P + "google.operation": "revoke", P + "outcome": "ok"},
    )


@pytest.mark.asyncio
async def test_revoke_http_error(mock_google, otel_spans):
    datasette = await make_datasette(mock_google)
    row = await add_oauth(datasette, mock_google)
    mock_google.faults.fail("/revoke", 500)
    result = await delete(datasette, ALICE, row.id)
    assert not result.revoked
    span = one(otel_spans, "oauth.revoke")
    assert attrs(span) == {
        P + "outcome": "http_error",
        "http.response.status_code": 500,
        P + "google.error": "_OTHER",
    }
    assert_error(span)


# --- request ------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_request_ok(mock_google, service_account_keys, otel_spans, otel_metrics):
    datasette = await make_datasette(mock_google)
    info = await add_sa(datasette, service_account_keys)
    cred = await get_credential(datasette, info.id, actor=ALICE, scopes=[SCOPE_SHEETS])
    otel_metrics.collect()
    response = await cred.request("get", STUDENTS)
    assert response.status_code == 200
    span = one(otel_spans, "request")
    assert attrs(span) == {
        P + "credential.id": info.id,
        P + "credential.type": "service_account",
        "http.request.method": "GET",
        "server.address": "sheets.googleapis.com",
        "http.response.status_code": 200,
        P + "retried": False,
    }
    assert span.status.status_code == StatusCode.UNSET
    assert [s.name for s in children(otel_spans, span)] == [P + "token"]
    otel_metrics.collect()
    point = otel_metrics.point(
        P + "request.duration",
        {
            P + "credential.type": "service_account",
            "http.request.method": "GET",
            "http.response.status_code": 200,
            P + "retried": False,
        },
    )
    assert point.count == 1


@pytest.mark.asyncio
async def test_request_401_retry(mock_google, otel_spans, otel_metrics):
    datasette = await make_datasette(mock_google)
    row = await add_oauth(datasette, mock_google)
    cred = await get_credential(datasette, row.id, actor=ALICE, scopes=[SCOPE_SHEETS])
    await cred.token()
    otel_spans.clear()
    otel_metrics.collect()
    mock_google.faults.fail("/v4/spreadsheets/", 401, times=1)
    response = await cred.request("GET", STUDENTS)
    assert response.status_code == 200

    span = one(otel_spans, "request")
    assert attrs(span)[P + "retried"] is True
    assert attrs(span)["http.response.status_code"] == 200
    first, second = children(otel_spans, span, "token")
    assert attrs(first)[P + "cache"] == "hit"
    assert attrs(second)[P + "cache"] == "miss"
    otel_metrics.collect()
    assert otel_metrics.point(
        P + "request.duration", {P + "retried": True, "http.response.status_code": 200}
    )


@pytest.mark.asyncio
async def test_request_exception_sets_error(
    mock_google, service_account_keys, otel_spans, otel_metrics
):
    datasette = await make_datasette(mock_google)
    info = await add_sa(datasette, service_account_keys)
    cred = await get_credential(datasette, info.id, actor=ALICE, scopes=[SCOPE_SHEETS])
    mock_google.faults.fail("/token", 503)
    with pytest.raises(GoogleTokenError):
        await cred.request("GET", STUDENTS)
    span = one(otel_spans, "request")
    assert attrs(span)["error.type"] == "GoogleTokenError"
    assert "http.response.status_code" not in attrs(span)
    assert_error(span)
    otel_metrics.collect()
    assert otel_metrics.point(
        P + "request.duration", {"error.type": "GoogleTokenError"}
    )


def test_clamp_google_error():
    assert clamp_google_error("weird_thing") == "_OTHER"
    assert clamp_google_error("invalid_grant") == "invalid_grant"
    assert clamp_google_error("admin_policy_enforced") == "admin_policy_enforced"
    assert clamp_google_error(None) is None
    assert clamp_google_error("") is None
