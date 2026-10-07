"""
OpenTelemetry integration for datasette-google-credentials (D29).

Like Datasette core, this plugin depends on ``opentelemetry-api`` only. It
never creates a ``TracerProvider`` or ``MeterProvider``, never configures an
exporter and never imports ``opentelemetry.sdk``: that is up to whoever runs
Datasette. With no provider installed every span is a ``NonRecordingSpan``
and every instrument a no-op proxy, so an instrumented call costs one
``perf_counter()`` pair; attribute work is skipped behind
``span.is_recording()``.

The tracer and meter live under their own ``datasette_google_credentials`` scope,
versioned with the plugin. Context propagates through contextvars, so these
spans nest inside core's request spans (and core's ``db.query`` spans nest
inside ours).

Every name comes from ``telemetry_registry``. Nothing secret or identifying
is recorded: see that module's docstring for the rules.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from importlib.metadata import version
from time import perf_counter
from typing import Any

import httpx2
from datasette.telemetry import SCHEMA_URL, clamp_http_method
from datasette.telemetry_registry import SpanName
from opentelemetry import metrics as otel_metrics
from opentelemetry import trace as otel_trace
from opentelemetry.trace import Span, Status, StatusCode

from .errors import (
    CredentialBroken,
    CredentialForbidden,
    CredentialNotFound,
    GoogleTokenError,
    MissingScopes,
)
from .http import google_error
from .telemetry_registry import (
    CACHE,
    CALLBACK_CREDENTIAL_ID,
    CALLBACK_RESULT,
    CREDENTIAL_ID,
    CREDENTIAL_TYPE,
    ERROR_TYPE,
    GOOGLE_ERROR,
    GOOGLE_ERROR_VALUES,
    GOOGLE_OPERATION,
    HTTP_REQUEST_METHOD,
    HTTP_RESPONSE_STATUS_CODE,
    M_CREDENTIALS_BROKEN,
    M_GOOGLE_DURATION,
    M_OAUTH_CALLBACKS,
    M_REQUEST_DURATION,
    M_TOKEN_CACHE_LOOKUPS,
    OAUTH_CALLBACK,
    OUTCOME,
    REQUEST,
    RETRIED,
    SCOPES_MISSING,
    SERVER_ADDRESS,
)

__version__ = version("datasette-google-credentials")

tracer = otel_trace.get_tracer(
    "datasette_google_credentials", __version__, schema_url=SCHEMA_URL
)
meter = otel_metrics.get_meter(
    "datasette_google_credentials", __version__, schema_url=SCHEMA_URL
)

# Module-level instruments are safe before any provider exists: proxy
# instruments forward once one is installed. Registry descriptions are
# Markdown for the docs; these are short plain sentences.
google_duration = meter.create_histogram(
    M_GOOGLE_DURATION,
    unit=M_GOOGLE_DURATION.unit,
    description="Duration of one call to a Google OAuth endpoint",
    explicit_bucket_boundaries_advisory=M_GOOGLE_DURATION.buckets,
)
token_cache_lookups = meter.create_counter(
    M_TOKEN_CACHE_LOOKUPS,
    unit=M_TOKEN_CACHE_LOOKUPS.unit,
    description="Token cache lookups by credential type and hit or miss",
)
request_duration = meter.create_histogram(
    M_REQUEST_DURATION,
    unit=M_REQUEST_DURATION.unit,
    description="Duration of an authenticated request to a Google API",
    explicit_bucket_boundaries_advisory=M_REQUEST_DURATION.buckets,
)
credentials_broken = meter.create_counter(
    M_CREDENTIALS_BROKEN,
    unit=M_CREDENTIALS_BROKEN.unit,
    description="Credentials marked broken after Google refused them",
)
oauth_callbacks = meter.create_counter(
    M_OAUTH_CALLBACKS,
    unit=M_OAUTH_CALLBACKS.unit,
    description="Connect Google callbacks by result",
)

# Access decisions, like an HTTP 4xx: recorded as error.type, not ERROR (D29).
ACCESS_DECISIONS = (CredentialNotFound, CredentialForbidden, MissingScopes)


def _span_kwargs(name: SpanName) -> dict[str, Any]:
    # The outcome classification decides what is an error, and exception
    # messages are never recorded (D29), so the SDK's automatic exception
    # event and status description are off.
    return {
        "kind": name.kind,
        "record_exception": False,
        "set_status_on_exception": False,
    }


def clamp_google_error(value: str | None) -> str | None:
    """Google's OAuth ``error`` if it is a known code, ``_OTHER`` if it is
    something else, ``None`` if there wasn't one."""
    if not value:
        return None
    return value if value in GOOGLE_ERROR_VALUES else "_OTHER"


def classify(exc: BaseException) -> str:
    """The ``outcome`` for an exception that ended a Google call."""
    if isinstance(exc, CredentialBroken):
        return "invalid_grant"
    if isinstance(exc, GoogleTokenError):
        if exc.status is None:
            return "network_error"
        if exc.status == 200:
            return "invalid_response"
    return "http_error"


# --- Google calls -------------------------------------------------------------


@dataclass
class GoogleCall:
    """What a ``google_call`` block learned, read when it exits."""

    span: Span
    status: int | None = None
    google_error: str | None = None
    outcome: str | None = None
    """Set explicitly only by calls that return a failure instead of raising."""

    def response(self, response: httpx2.Response) -> None:
        """Record Google's reply: its status and, if it failed, the clamped
        OAuth ``error`` code (never the description)."""
        self.status = response.status_code
        if response.status_code != 200:
            self.google_error = clamp_google_error(google_error(response)[0])

    def set(self, key: str, value: Any) -> None:
        if self.span.is_recording():
            self.span.set_attribute(key, value)


@contextmanager
def google_call(operation: str, span_name: SpanName) -> Iterator[GoogleCall]:
    """A CLIENT span plus ``google.duration`` around one Google call.

    Status is ``ERROR`` (no description) whenever the outcome isn't ``ok``.
    """
    started = perf_counter()
    with tracer.start_as_current_span(span_name, **_span_kwargs(span_name)) as span:
        call = GoogleCall(span)
        error_type = None
        try:
            yield call
        except BaseException as exc:
            if call.outcome is None:
                call.outcome = classify(exc)
            error_type = type(exc).__name__
            raise
        finally:
            outcome = call.outcome or "ok"
            attributes: dict[str, Any] = {GOOGLE_OPERATION: operation, OUTCOME: outcome}
            if call.google_error:
                attributes[GOOGLE_ERROR] = call.google_error
            google_duration.record(perf_counter() - started, attributes)
            if span.is_recording():
                span.set_attribute(OUTCOME, outcome)
                if call.status is not None:
                    span.set_attribute(HTTP_RESPONSE_STATUS_CODE, call.status)
                if call.google_error:
                    span.set_attribute(GOOGLE_ERROR, call.google_error)
                if error_type is not None:
                    span.set_attribute(ERROR_TYPE, error_type)
                if outcome != "ok":
                    span.set_status(Status(StatusCode.ERROR))


# --- Broker ---------------------------------------------------------------------


def _fail(span: Span, exc: BaseException) -> None:
    if span.is_recording():
        span.set_attribute(ERROR_TYPE, type(exc).__name__)
        if not isinstance(exc, ACCESS_DECISIONS):
            span.set_status(Status(StatusCode.ERROR))


@contextmanager
def credential_span(span_name: SpanName, credential_id: str) -> Iterator[Span]:
    """An INTERNAL span for broker work on one credential. An escaping
    exception sets ``error.type``, and ``ERROR`` unless it is an access
    decision."""
    with tracer.start_as_current_span(span_name, **_span_kwargs(span_name)) as span:
        if span.is_recording():
            span.set_attribute(CREDENTIAL_ID, credential_id)
        try:
            yield span
        except BaseException as exc:
            _fail(span, exc)
            raise


def _host(url: str) -> str | None:
    """The URL's host only (never userinfo, path or query), parsed as the
    httpx2 client that sends the request parses it."""
    try:
        return httpx2.URL(url).raw_host.decode("ascii").lower() or None
    except (httpx2.InvalidURL, TypeError, UnicodeDecodeError):
        return None


@dataclass
class RequestCall:
    status: int | None = None
    retried: bool = False


@contextmanager
def request_call(
    credential_id: str, credential_type: str, method: str, url: str
) -> Iterator[RequestCall]:
    """The ``request`` span and ``request.duration`` around
    ``Credential.request()``. Records only the URL's host."""
    started = perf_counter()
    call = RequestCall()
    base: dict[str, Any] = {
        CREDENTIAL_TYPE: credential_type,
        HTTP_REQUEST_METHOD: clamp_http_method(method),
    }
    with credential_span(REQUEST, credential_id) as span:
        if span.is_recording():
            span.set_attributes(base)
            host = _host(url)
            if host:
                span.set_attribute(SERVER_ADDRESS, host)
        error_type = None
        try:
            yield call
        except BaseException as exc:
            error_type = type(exc).__name__
            raise
        finally:
            attributes: dict[str, Any] = dict(base)
            attributes[RETRIED] = call.retried
            if call.status is not None:
                attributes[HTTP_RESPONSE_STATUS_CODE] = call.status
            if span.is_recording():
                span.set_attributes(attributes)
            if error_type is not None:
                attributes[ERROR_TYPE] = error_type
            request_duration.record(perf_counter() - started, attributes)


def record_cache_lookup(credential_type: str, hit: bool) -> None:
    "Count one token-cache lookup."
    token_cache_lookups.add(
        1, {CREDENTIAL_TYPE: credential_type, CACHE: "hit" if hit else "miss"}
    )


def record_broken(credential_type: str) -> None:
    credentials_broken.add(1, {CREDENTIAL_TYPE: credential_type})


# --- Connect Google callback ---------------------------------------------------

# Callback results that are the plugin's or Google's failure, not the user's.
_CALLBACK_ERRORS = frozenset(
    {
        "google_error",
        "no_refresh_token",
        "invalid_grant",
        "token_error",
        "not_configured",
    }
)


@dataclass
class Callback:
    result: str | None = None
    credential_id: str | None = None
    google_error: str | None = None
    scopes_missing: int | None = None


@contextmanager
def callback_span() -> Iterator[Callback]:
    """The ``oauth.callback`` span and ``oauth.callbacks`` counter. The body
    sets ``result`` before every return."""
    with tracer.start_as_current_span(
        OAUTH_CALLBACK, **_span_kwargs(OAUTH_CALLBACK)
    ) as span:
        callback = Callback()
        failed = False
        try:
            yield callback
        except BaseException as exc:
            failed = True
            _fail(span, exc)
            raise
        finally:
            if callback.result is not None:
                oauth_callbacks.add(1, {CALLBACK_RESULT: callback.result})
            if span.is_recording():
                if callback.result is not None:
                    span.set_attribute(CALLBACK_RESULT, callback.result)
                if callback.credential_id is not None:
                    span.set_attribute(CALLBACK_CREDENTIAL_ID, callback.credential_id)
                if callback.google_error is not None:
                    span.set_attribute(GOOGLE_ERROR, callback.google_error)
                if callback.scopes_missing is not None:
                    span.set_attribute(SCOPES_MISSING, callback.scopes_missing)
                if not failed and callback.result in _CALLBACK_ERRORS:
                    span.set_status(Status(StatusCode.ERROR))
