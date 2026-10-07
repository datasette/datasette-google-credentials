"""
The single source of truth for every span and metric datasette-google-credentials
emits (D29).

Three things read this module:

1. **The instrumentation** in `telemetry.py` and the call sites it serves.
   Entries subclass `str` (they are instances of core's public registry
   classes), so a registry entry *is* the name OpenTelemetry wants, and a
   typo is an `ImportError` instead of a silently misnamed signal.
2. **The generated reference** in the README (`scripts/telemetry-doc.py`).
   Descriptions are Markdown.
3. **The conformance test** `tests/test_telemetry_registry.py`, which runs a
   broad workload against the mock Google and asserts both directions:
   everything emitted is registered (enum membership included) and
   everything registered is emitted.

Naming: the instrumentation scope is the import package name
(`datasette_google_credentials`), and so is the prefix of every plugin-specific
signal. `error.type`, `http.*` and `server.address` reuse the semantic
convention keys, as our own `Attribute` instances (core's carry core's prose).

Privacy: no token, code, verifier, `state`, key material, client secret,
email, actor/owner id, label, URL path or query, Google `error_description`
or exception message is ever recorded. Credential ids ride on spans only,
never on a metric.
"""

from datasette.telemetry_registry import (
    COUNTER,
    HISTOGRAM,
    Attribute,
    MetricName,
    SpanName,
)
from opentelemetry.trace import SpanKind

__all__ = [
    "COUNTER",
    "GOOGLE_DURATION_BUCKETS",
    "HISTOGRAM",
    "METRICS",
    "SPANS",
]

# --- Attributes -----------------------------------------------------------

CREDENTIAL_TYPE = Attribute(
    "datasette_google_credentials.credential.type",
    "`service_account` or `google_oauth`.",
    values={"service_account", "google_oauth"},
)
CREDENTIAL_ID = Attribute(
    "datasette_google_credentials.credential.id",
    "The credential's ULID. Opaque, and **spans only, never a metric "
    "dimension**. Owner, actor and email are never recorded.",
)
# The callback span only knows the id once the credential is saved.
CALLBACK_CREDENTIAL_ID = Attribute(
    "datasette_google_credentials.credential.id",
    "The ULID of the credential created or reconnected. Set on success only.",
    optional=True,
)
CACHE = Attribute(
    "datasette_google_credentials.cache",
    "`hit` if the token came from the in-memory token cache, `miss` if it "
    "was minted or refreshed.",
    values={"hit", "miss"},
)
TOKEN_CACHE = Attribute(
    "datasette_google_credentials.cache",
    "`hit` or `miss`. Set once the token is in hand; absent when access "
    "was denied or the fetch failed.",
    optional=True,
    values={"hit", "miss"},
)
TOKEN_CREDENTIAL_TYPE = Attribute(
    "datasette_google_credentials.credential.type",
    "`service_account` or `google_oauth`. Set once the credential has been "
    "re-read; absent when it doesn't exist or the actor can't see it.",
    optional=True,
    values={"service_account", "google_oauth"},
)
GOOGLE_OPERATION = Attribute(
    "datasette_google_credentials.google.operation",
    "Which Google call: `mint` (service-account JWT exchange), `refresh`, "
    "`exchange` (authorization code), `userinfo` or `revoke`. On the "
    "metric only: span names already carry it.",
    values={"mint", "refresh", "exchange", "userinfo", "revoke"},
)
OUTCOME = Attribute(
    "datasette_google_credentials.outcome",
    "How the Google call ended: `ok`; `invalid_grant` (key deleted or "
    "disabled, grant revoked, code reused); `http_error` (any other non-200); "
    "`network_error` (Google never answered); `invalid_response` (a 200 "
    "without the expected fields).",
    values={"ok", "invalid_grant", "http_error", "network_error", "invalid_response"},
)
GOOGLE_ERROR_VALUES = frozenset(
    {
        # RFC 6749 5.2 (token endpoint)
        "invalid_request",
        "invalid_client",
        "invalid_grant",
        "unauthorized_client",
        "unsupported_grant_type",
        "invalid_scope",
        # RFC 6749 4.1.2.1 (authorization endpoint, reaches the callback)
        "access_denied",
        "unsupported_response_type",
        "server_error",
        "temporarily_unavailable",
        # RFC 7009 and Google's revoke endpoint
        "invalid_token",
        "unsupported_token_type",
        # Google-specific, from its web-server OAuth guide
        "admin_policy_enforced",
        "disallowed_useragent",
        "org_internal",
        "deleted_client",
        "redirect_uri_mismatch",
        "_OTHER",
    }
)
GOOGLE_ERROR = Attribute(
    "datasette_google_credentials.google.error",
    "Google's OAuth `error` code, from a failed reply or the callback's "
    "`error` parameter. Clamped to the RFC 6749 / RFC 7009 codes plus "
    "Google's documented ones; anything else is `_OTHER`. Never the "
    "`error_description`.",
    optional=True,
    values=GOOGLE_ERROR_VALUES,
)
CALLBACK_RESULT = Attribute(
    "datasette_google_credentials.callback.result",
    "How the Connect Google callback ended: `created` / `reconnected` "
    "(success); `cancelled` (the user clicked Cancel); `google_error` (Google "
    "sent another `error`); `invalid_state` (bad, expired or foreign state or "
    "flow cookie); `no_code`; `no_refresh_token`; `invalid_grant` (the code "
    "exchange was refused); `token_error` (any other Google failure); "
    "`not_configured` (no `encryption-key`). Absent only when an unexpected "
    "exception escaped.",
    values={
        "created",
        "reconnected",
        "cancelled",
        "google_error",
        "invalid_state",
        "no_code",
        "no_refresh_token",
        "invalid_grant",
        "token_error",
        "not_configured",
    },
)
SCOPES_COUNT = Attribute(
    "datasette_google_credentials.scopes.count",
    "How many scopes the service-account token was minted for.",
)
SCOPES_MISSING = Attribute(
    "datasette_google_credentials.scopes.missing",
    "How many configured API scopes the user didn't grant (partial consent). "
    "Set on success only; `0` when everything was granted.",
    optional=True,
)
REFRESH_TOKEN_ROTATED = Attribute(
    "datasette_google_credentials.refresh_token.rotated",
    "`True` if Google returned a new refresh token. Set on success only.",
    optional=True,
)
RETRIED = Attribute(
    "datasette_google_credentials.retried",
    "`True` if the first response was a 401, so the cached token was evicted "
    "and the request retried once with a fresh one.",
)
HTTP_REQUEST_METHOD = Attribute(
    "http.request.method",
    "The request method, clamped by core's `clamp_http_method` (anything "
    "outside RFC 9110 + PATCH is `_OTHER`).",
)
HTTP_RESPONSE_STATUS_CODE = Attribute(
    "http.response.status_code",
    "The HTTP status of Google's reply. Absent when Google never answered.",
    optional=True,
)
REQUEST_STATUS_CODE = Attribute(
    "http.response.status_code",
    "The HTTP status of the API's reply: the retry's, after a 401. Absent "
    "when no response arrived.",
    optional=True,
)
SERVER_ADDRESS = Attribute(
    "server.address",
    "The host of the requested URL. Never the path or query.",
)
ERROR_TYPE = Attribute(
    "error.type",
    "Class name of the exception that ended the operation. Never the message.",
    optional=True,
)

# --- Spans ----------------------------------------------------------------

_GOOGLE_STATUS = (
    " Status is `ERROR` (with no description) whenever `outcome` isn't `ok`."
)

TOKEN = SpanName(
    "datasette_google_credentials.token",
    "`Credential.token()`: re-reading the credential, re-checking access, "
    "then serving from the token cache or minting/refreshing. On a cache "
    "miss the `token.mint` or `token.refresh` span is its child. Status is "
    "`ERROR` for any exception except the access decisions "
    "`CredentialNotFound`, `CredentialForbidden` and `MissingScopes`, which "
    "are outcomes (like an HTTP 4xx) and only set `error.type`.",
    (CREDENTIAL_ID, TOKEN_CREDENTIAL_TYPE, TOKEN_CACHE, ERROR_TYPE),
)
REQUEST = SpanName(
    "datasette_google_credentials.request",
    "`Credential.request()`: one authenticated call to a Google API, with "
    "its `token` span(s) as children (two on a 401 retry). A returned 4xx "
    "or 5xx is the consumer's to handle and leaves the status unset; status "
    "is `ERROR` only when an exception escapes, other than the access "
    "decisions the `token` span also exempts.",
    (
        CREDENTIAL_ID,
        CREDENTIAL_TYPE,
        HTTP_REQUEST_METHOD,
        SERVER_ADDRESS,
        REQUEST_STATUS_CODE,
        RETRIED,
        ERROR_TYPE,
    ),
)
TOKEN_MINT = SpanName(
    "datasette_google_credentials.token.mint",
    "A service-account JWT-bearer exchange at Google's token endpoint, for "
    "the broker or the live test when a key is added or rotated." + _GOOGLE_STATUS,
    (SCOPES_COUNT, OUTCOME, HTTP_RESPONSE_STATUS_CODE, GOOGLE_ERROR, ERROR_TYPE),
    kind=SpanKind.CLIENT,
)
TOKEN_REFRESH = SpanName(
    "datasette_google_credentials.token.refresh",
    "An OAuth refresh-token grant at Google's token endpoint." + _GOOGLE_STATUS,
    (
        OUTCOME,
        HTTP_RESPONSE_STATUS_CODE,
        GOOGLE_ERROR,
        REFRESH_TOKEN_ROTATED,
        ERROR_TYPE,
    ),
    kind=SpanKind.CLIENT,
)
OAUTH_EXCHANGE = SpanName(
    "datasette_google_credentials.oauth.exchange",
    "The authorization-code (+ PKCE verifier) exchange during the Connect "
    "Google callback." + _GOOGLE_STATUS,
    (OUTCOME, HTTP_RESPONSE_STATUS_CODE, GOOGLE_ERROR, ERROR_TYPE),
    kind=SpanKind.CLIENT,
)
OAUTH_USERINFO = SpanName(
    "datasette_google_credentials.oauth.userinfo",
    "The OpenID userinfo call that identifies the Google account during the "
    "Connect Google callback." + _GOOGLE_STATUS,
    (OUTCOME, HTTP_RESPONSE_STATUS_CODE, GOOGLE_ERROR, ERROR_TYPE),
    kind=SpanKind.CLIENT,
)
OAUTH_REVOKE = SpanName(
    "datasette_google_credentials.oauth.revoke",
    "Best-effort revocation of a refresh token when an OAuth credential is "
    "deleted. The delete goes ahead either way." + _GOOGLE_STATUS,
    (OUTCOME, HTTP_RESPONSE_STATUS_CODE, GOOGLE_ERROR, ERROR_TYPE),
    kind=SpanKind.CLIENT,
)
OAUTH_CALLBACK = SpanName(
    "datasette_google_credentials.oauth.callback",
    "The Connect Google callback (`GET /-/google-credentials/oauth/callback`) once "
    "the actor is allowed to connect, child of core's request span, with "
    "the `oauth.exchange` and `oauth.userinfo` spans as children. Status is "
    "`ERROR` for `google_error`, `no_refresh_token`, `invalid_grant`, "
    "`token_error`, `not_configured` or an unexpected exception; a user "
    "cancelling or a stale link is not an error.",
    (
        CALLBACK_RESULT,
        CALLBACK_CREDENTIAL_ID,
        GOOGLE_ERROR,
        SCOPES_MISSING,
        ERROR_TYPE,
    ),
)

SPANS: tuple[SpanName, ...] = (
    TOKEN,
    REQUEST,
    TOKEN_MINT,
    TOKEN_REFRESH,
    OAUTH_EXCHANGE,
    OAUTH_USERINFO,
    OAUTH_REVOKE,
    OAUTH_CALLBACK,
)

# --- Metrics --------------------------------------------------------------

# Seconds, capped at 10 s: that is http.TIMEOUT, so nothing takes longer.
GOOGLE_DURATION_BUCKETS = (0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10)

M_GOOGLE_DURATION = MetricName(
    "datasette_google_credentials.google.duration",
    HISTOGRAM,
    "s",
    "Duration of one call to a Google OAuth endpoint, by operation and "
    "outcome. Its counts are the token fetches by type and outcome: "
    "`operation=mint` is service accounts (live tests of new keys "
    "included), `operation=refresh` is OAuth.",
    (GOOGLE_OPERATION, OUTCOME, GOOGLE_ERROR),
    buckets=GOOGLE_DURATION_BUCKETS,
)
M_TOKEN_CACHE_LOOKUPS = MetricName(
    "datasette_google_credentials.token_cache.lookups",
    COUNTER,
    "{lookup}",
    "Token-cache lookups by credential type and `hit` / `miss`. Hit ratio "
    "is hits over the total.",
    (CREDENTIAL_TYPE, CACHE),
)
M_REQUEST_DURATION = MetricName(
    "datasette_google_credentials.request.duration",
    HISTOGRAM,
    "s",
    "Duration of `Credential.request()`, token fetches and a 401 retry included.",
    (
        CREDENTIAL_TYPE,
        HTTP_REQUEST_METHOD,
        REQUEST_STATUS_CODE,
        RETRIED,
        ERROR_TYPE,
    ),
    buckets=GOOGLE_DURATION_BUCKETS,
)
M_CREDENTIALS_BROKEN = MetricName(
    "datasette_google_credentials.credentials.broken",
    COUNTER,
    "{credential}",
    "Credentials marked broken because Google refused them (`invalid_grant`). "
    "Counted only when the compare-and-swap lands, so a race with a "
    "reconnect or rotation isn't counted.",
    (CREDENTIAL_TYPE,),
)
M_OAUTH_CALLBACKS = MetricName(
    "datasette_google_credentials.oauth.callbacks",
    COUNTER,
    "{callback}",
    "Connect Google callbacks by result.",
    (CALLBACK_RESULT,),
)

METRICS: tuple[MetricName, ...] = (
    M_GOOGLE_DURATION,
    M_TOKEN_CACHE_LOOKUPS,
    M_REQUEST_DURATION,
    M_CREDENTIALS_BROKEN,
    M_OAUTH_CALLBACKS,
)
