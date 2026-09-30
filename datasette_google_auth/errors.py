"""Exceptions raised by datasette-google-auth.

Every error subclasses ``GoogleAuthError`` and carries a stable ``code``
string, so consumers can branch on it without matching message text.
``error_response()`` turns any of them into a consistent JSON error.

Messages are shown to users: never put a token, key or ciphertext in one.
"""

from __future__ import annotations

from typing import Any

from datasette import Response

ENCRYPTION_NOT_CONFIGURED = "datasette-google-auth needs `encryption-key` configured"


class GoogleAuthError(Exception):
    """Base class for every datasette-google-auth error."""

    code = "google_auth_error"


class EncryptionNotConfigured(GoogleAuthError):
    """No ``encryption-key``: credentials can't be stored or read."""

    code = "encryption_not_configured"

    def __init__(self, message: str = ENCRYPTION_NOT_CONFIGURED):
        super().__init__(message)


class CredentialUndecryptable(GoogleAuthError):
    """None of the configured keys decrypts a stored credential.

    Usually the ``encryption-key`` was changed without keeping the old key in
    the list. The row is left alone: restoring the old key fixes it.
    """

    code = "credential_undecryptable"

    def __init__(self, credential_id: str):
        self.credential_id = credential_id
        super().__init__(
            f"Credential {credential_id}: cannot decrypt — was encryption-key changed?"
        )


class CredentialNotFound(GoogleAuthError):
    """No such credential, or one the actor may not know exists.

    The two are deliberately indistinguishable (D11: no ID probing).
    """

    code = "not_found"

    def __init__(self, credential_id: str):
        self.credential_id = credential_id
        super().__init__(f"Credential not found: {credential_id}")


class CredentialForbidden(GoogleAuthError):
    """The actor may see the credential (or feature) but not do this with it."""

    code = "forbidden"

    def __init__(self, message: str = "Permission denied"):
        super().__init__(message)


class CredentialBroken(GoogleAuthError):
    """Google rejected the credential (``invalid_grant``): the key was deleted
    or disabled, or the OAuth grant revoked. Needs a new key or a reconnect.

    ``detail`` is Google's ``error_description``, which carries no secrets.
    ``reconnect_url`` is set for OAuth credentials the actor owns.
    """

    code = "credential_broken"

    def __init__(
        self,
        detail: str,
        *,
        credential_id: str | None = None,
        reconnect_url: str | None = None,
    ):
        self.detail = detail
        self.credential_id = credential_id
        self.reconnect_url = reconnect_url
        subject = f"Credential {credential_id}" if credential_id else "Credential"
        super().__init__(f"{subject} was rejected by Google: {detail}")


class CredentialChanged(GoogleAuthError):
    """The credential was replaced (reconnected, rotated) while it was being
    used, twice in a row. Nothing was written; trying again should work."""

    code = "credential_changed"

    def __init__(self, credential_id: str):
        self.credential_id = credential_id
        super().__init__(
            f"Credential {credential_id} changed while it was being used — try again"
        )


class MissingScopes(GoogleAuthError):
    """An OAuth credential wasn't granted every requested scope.

    ``reconnect_url`` is set when reconnecting can fix it: every missing
    scope is in the configured ``scopes``, which connect asks for again.
    ``not_configured`` lists missing scopes this instance never requests;
    only an administrator adding them to ``scopes`` can fix those.
    """

    code = "missing_scopes"

    def __init__(
        self,
        missing: list[str],
        *,
        reconnect_url: str | None = None,
        not_configured: list[str] | None = None,
    ):
        self.missing = list(missing)
        self.reconnect_url = reconnect_url
        self.not_configured = list(not_configured or [])
        message = "Credential is missing required scopes: " + " ".join(self.missing)
        if self.not_configured:
            message += (
                ". This Datasette instance doesn't request "
                + " ".join(self.not_configured)
                + ": an administrator must add it to the datasette-google-auth"
                " `scopes` setting"
            )
        super().__init__(message)


class GoogleTokenError(GoogleAuthError):
    """A Google token endpoint failed for a reason other than ``invalid_grant``
    (5xx, ``invalid_scope``, a network error, a malformed reply).

    ``status`` is the HTTP status (``None`` if Google was never reached);
    ``error`` / ``description`` are Google's ``error`` and
    ``error_description``, which contain no secrets.
    """

    code = "google_error"

    def __init__(
        self,
        status: int | None,
        error: str | None = None,
        description: str | None = None,
    ):
        self.status = status
        self.error = error
        self.description = description
        where = f"HTTP {status}" if status is not None else "no response"
        reason = ": ".join(part for part in (error, description) if part)
        super().__init__(
            f"Google token request failed ({where})" + (f": {reason}" if reason else "")
        )


class InvalidServiceAccountKey(GoogleAuthError):
    """A pasted service-account key was rejected, locally or by Google's test
    exchange. The message names the problem and never echoes key material."""

    code = "invalid_service_account_key"


class InvalidLabel(GoogleAuthError):
    """A credential label was empty or too long."""

    code = "invalid_label"


class DisallowedHost(GoogleAuthError):
    """``Credential.request()`` refused to send the bearer token to a URL that
    isn't ``https://`` on a Google API host (``*.googleapis.com``) or on the
    origin of a configured ``google_base_urls`` entry (D34). Nothing was
    sent and no token was fetched. ``allow_any_host=True`` overrides it.

    ``host`` is the refused URL's host (``None`` if it had none). The message
    names only the scheme and host, never the path, query or userinfo.
    """

    code = "disallowed_host"

    def __init__(self, origin: str, host: str | None, reason: str):
        self.host = host
        self.reason = reason
        super().__init__(
            f"Refusing to send a Google access token to {origin}: {reason}."
            " Credential.request() only calls https://*.googleapis.com"
            " (pass allow_any_host=True to override)"
        )


# --- JSON error responses -----------------------------------------------------

# HTTP status per error class. ``error_response`` walks the MRO, so a subclass
# added later inherits its parent's status (``GoogleAuthError`` itself: 500).
_STATUS: dict[type[GoogleAuthError], int] = {
    CredentialNotFound: 404,
    CredentialForbidden: 403,
    # RFC 6750 `insufficient_scope` is a 403 too; `code` tells them apart.
    MissingScopes: 403,
    CredentialBroken: 409,
    CredentialChanged: 409,
    InvalidServiceAccountKey: 400,
    InvalidLabel: 400,
    DisallowedHost: 400,
    GoogleTokenError: 502,
    EncryptionNotConfigured: 503,
    CredentialUndecryptable: 500,
    GoogleAuthError: 500,
}


def error_status(exc: GoogleAuthError) -> int:
    """The HTTP status ``error_response`` uses for ``exc``."""
    for cls in type(exc).__mro__:
        status = _STATUS.get(cls)
        if status is not None:
            return status
    return 500


def error_response(exc: GoogleAuthError) -> Response:
    """A consumer-facing JSON error for any ``GoogleAuthError``::

        {"ok": false, "error": "<message>", "code": "<exc.code>",
         "reconnect_url": "...",   # only when reconnecting can fix it
         "missing": [...]}         # MissingScopes only

    Messages never contain secrets (see the module docstring), so ``error``
    is safe to show.
    """
    body: dict[str, Any] = {"ok": False, "error": str(exc), "code": exc.code}
    reconnect_url = getattr(exc, "reconnect_url", None)
    if reconnect_url:
        body["reconnect_url"] = reconnect_url
    if isinstance(exc, MissingScopes):
        body["missing"] = exc.missing
    return Response.json(body, status=error_status(exc))
