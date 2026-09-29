"""Exceptions raised by datasette-google-auth.

Ticket 10 defines the full consumer-facing set (``CredentialNotFound``,
``CredentialForbidden``, ``CredentialBroken``, ``MissingScopes``...) on the
same ``GoogleAuthError`` base; add them here.

Messages are shown to users: never put a token, key or ciphertext in one.
"""

from __future__ import annotations

ENCRYPTION_NOT_CONFIGURED = "datasette-google-auth needs `encryption-key` configured"


class GoogleAuthError(Exception):
    """Base class for every datasette-google-auth error."""


class EncryptionNotConfigured(GoogleAuthError):
    """No ``encryption-key``: credentials can't be stored or read."""

    def __init__(self, message: str = ENCRYPTION_NOT_CONFIGURED):
        super().__init__(message)


class CredentialUndecryptable(GoogleAuthError):
    """None of the configured keys decrypts a stored credential.

    Usually the ``encryption-key`` was changed without keeping the old key in
    the list. The row is left alone: restoring the old key fixes it.
    """

    def __init__(self, credential_id: str):
        self.credential_id = credential_id
        super().__init__(
            f"Credential {credential_id}: cannot decrypt — was encryption-key changed?"
        )
