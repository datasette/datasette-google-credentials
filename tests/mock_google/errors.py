"""Google-shaped error responses.

Two wire formats:

- Google APIs (Sheets, and userinfo's 403) use the ``google.rpc.Status``
  envelope: ``{"error": {"code", "message", "status", "details"?}}``.
- The OAuth endpoints (``/token``, ``/revoke``, ``/o/oauth2/v2/auth``) use the
  flat RFC 6749 shape: ``{"error": "invalid_grant", "error_description": "..."}``.
"""

from __future__ import annotations

from fastapi.responses import JSONResponse

JSON_UTF8 = "application/json; charset=UTF-8"
ERROR_INFO = "type.googleapis.com/google.rpc.ErrorInfo"

UNAUTHENTICATED_MESSAGE = (
    "Request had invalid authentication credentials. Expected OAuth 2 access token, "
    "login cookie or other valid authentication credential. "
    "See https://developers.google.com/identity/sign-in/web/devconsole-project."
)
MISSING_CREDENTIALS_MESSAGE = (
    "Method doesn't allow unregistered callers (callers without established identity). "
    "Please use API Key or other form of API consumer identity to call this API."
)

# status code -> google.rpc status name, for injected faults.
STATUS_NAMES = {
    400: "INVALID_ARGUMENT",
    401: "UNAUTHENTICATED",
    403: "PERMISSION_DENIED",
    404: "NOT_FOUND",
    409: "ALREADY_EXISTS",
    429: "RESOURCE_EXHAUSTED",
    500: "INTERNAL",
    503: "UNAVAILABLE",
}


def google_error(
    code: int,
    status: str,
    message: str,
    reason: str | None = None,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    error: dict = {"code": code, "message": message, "status": status}
    if reason is not None:
        error["details"] = [
            {"@type": ERROR_INFO, "reason": reason, "domain": "googleapis.com"}
        ]
    return JSONResponse(
        {"error": error}, status_code=code, headers=headers, media_type=JSON_UTF8
    )


def unauthenticated() -> JSONResponse:
    """401 for an unknown, expired or revoked bearer token."""
    return google_error(
        401,
        "UNAUTHENTICATED",
        UNAUTHENTICATED_MESSAGE,
        headers={
            "WWW-Authenticate": 'Bearer realm="https://accounts.google.com/", error="invalid_token"'
        },
    )


def missing_credentials() -> JSONResponse:
    return google_error(403, "PERMISSION_DENIED", MISSING_CREDENTIALS_MESSAGE)


def insufficient_scope(scope: str) -> JSONResponse:
    return google_error(
        403,
        "PERMISSION_DENIED",
        "Request had insufficient authentication scopes.",
        reason="ACCESS_TOKEN_SCOPE_INSUFFICIENT",
        headers={
            "WWW-Authenticate": 'Bearer realm="https://accounts.google.com/", '
            f'error="insufficient_scope", scope="{scope}"'
        },
    )


def permission_denied() -> JSONResponse:
    return google_error(403, "PERMISSION_DENIED", "The caller does not have permission")


def not_found() -> JSONResponse:
    return google_error(404, "NOT_FOUND", "Requested entity was not found.")


def invalid_argument(message: str) -> JSONResponse:
    return google_error(400, "INVALID_ARGUMENT", message)


def unable_to_parse_range(range_: str) -> JSONResponse:
    return invalid_argument(f"Unable to parse range: {range_}")


def for_status(status: int) -> JSONResponse:
    """A plausible Google API error for an injected fault."""
    if status == 401:
        return unauthenticated()
    name = STATUS_NAMES.get(status, "UNKNOWN")
    return google_error(status, name, f"mock_google: injected {status}")


def oauth_error(
    error: str, description: str | None = None, status: int = 400
) -> JSONResponse:
    body = {"error": error}
    if description is not None:
        body["error_description"] = description
    return JSONResponse(body, status_code=status, media_type=JSON_UTF8)
