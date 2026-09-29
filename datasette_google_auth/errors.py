"""Exceptions raised by datasette-google-auth.

Every error subclasses ``GoogleAuthError`` and carries a stable ``code``
string, so consumers (and ticket 10's JSON error helper) can branch on it
without matching message text.

Messages are shown to users: never put a token, key or ciphertext in one.
"""

from __future__ import annotations

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


class MissingScopes(GoogleAuthError):
    """An OAuth credential wasn't granted every requested scope."""

    code = "missing_scopes"

    def __init__(self, missing: list[str], *, reconnect_url: str | None = None):
        self.missing = list(missing)
        self.reconnect_url = reconnect_url
        super().__init__(
            "Credential is missing required scopes: " + " ".join(self.missing)
        )


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
