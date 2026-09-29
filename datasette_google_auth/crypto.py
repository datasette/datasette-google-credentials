"""Encryption at rest for credential secrets (D7).

Secrets (service-account key fields, OAuth refresh tokens) are JSON dicts,
encrypted with Fernet into ``secret_encrypted``. ``encryption-key`` may be a
list: the first key encrypts, every key decrypts (``MultiFernet``), so a key
can be rotated by prepending a new one. Rows still under an old key are
re-encrypted lazily when read (``decrypt_credential``), or all at once with
``datasette google-auth rotate-keys`` (``rotate_all_credentials``).

Nothing here logs, and no error message includes a key, a token or
ciphertext.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from cryptography.fernet import Fernet, InvalidToken, MultiFernet

from .config import get_config
from .errors import CredentialUndecryptable, EncryptionNotConfigured
from .internal_db import CredentialRow, InternalDB

if TYPE_CHECKING:
    from datasette.app import Datasette


class InvalidEncryptionKey(ValueError):
    """A configured key isn't a Fernet key. The message never includes it."""


class SecretBox:
    """Encrypts and decrypts secret dicts with one or more Fernet keys.

    ``keys`` is newest first: ``keys[0]`` encrypts, all of them decrypt.
    """

    def __init__(self, keys: list[str]):
        if not keys:
            raise ValueError("SecretBox needs at least one key")
        fernets = []
        for position, key in enumerate(keys, start=1):
            try:
                fernets.append(Fernet(key))
            except (ValueError, TypeError):
                # Fernet's own message doesn't echo the key either, but don't
                # chain it: the key's position is all the user needs.
                where = f"key {position} of {len(keys)}" if len(keys) > 1 else "key"
                raise InvalidEncryptionKey(
                    f"{where} is not a valid Fernet key (expected 32 url-safe"
                    " base64-encoded bytes). Generate one with"
                    " `datasette google-auth generate-key`."
                ) from None
        self._primary = fernets[0]
        self._f = MultiFernet(fernets)

    def __repr__(self) -> str:
        return "<SecretBox>"

    def encrypt(self, data: dict) -> bytes:
        return self._f.encrypt(json.dumps(data).encode("utf-8"))

    def decrypt(self, token: bytes) -> dict:
        """Raises ``InvalidToken`` if no configured key decrypts ``token``."""
        return json.loads(self._f.decrypt(token))

    def needs_rotation(self, token: bytes) -> bool:
        """True if ``token`` was encrypted with a key other than the primary.

        Checks the HMAC only, without decrypting. Raises ``InvalidToken`` if
        no configured key matches.
        """
        try:
            self._primary.extract_timestamp(token)
            return False
        except InvalidToken:
            pass
        self._f.extract_timestamp(token)
        return True

    def rotate(self, token: bytes) -> bytes:
        """Re-encrypt ``token`` with the primary key (keeps its timestamp).

        ``MultiFernet.rotate`` re-encrypts unconditionally: check
        ``needs_rotation`` first to avoid pointless writes.
        """
        return self._f.rotate(token)


def build_box(keys: list[str]) -> SecretBox | None:
    """A ``SecretBox`` for these keys, or ``None`` if there are none.

    Raises ``InvalidEncryptionKey`` for malformed key material.
    """
    return SecretBox(keys) if keys else None


def get_box(datasette: Datasette) -> SecretBox | None:
    """The ``SecretBox`` from plugin config, or ``None`` if not configured."""
    return build_box(get_config(datasette).encryption_keys)


def require_box(datasette: Datasette) -> SecretBox:
    """Like ``get_box``, but raises ``EncryptionNotConfigured`` instead of
    returning ``None``. Every path that stores or reads a secret uses this."""
    box = get_box(datasette)
    if box is None:
        raise EncryptionNotConfigured()
    return box


def encrypt_secret(datasette: Datasette, data: dict) -> bytes:
    """Encrypt a secret dict for ``secret_encrypted``.

    Raises ``EncryptionNotConfigured`` without a key: no credential can be
    written unencrypted.
    """
    return require_box(datasette).encrypt(data)


async def decrypt_credential(datasette: Datasette, row: CredentialRow) -> dict:
    """Decrypt a credential's secret, re-encrypting it with the primary key if
    it was stored under an older one (lazy rotation).

    Raises ``EncryptionNotConfigured`` or ``CredentialUndecryptable``.
    Callers must not hold on to the returned dict beyond the call that needs
    it.
    """
    box = require_box(datasette)
    token = row.secret_encrypted
    try:
        data = box.decrypt(token)
        stale = box.needs_rotation(token)
    except InvalidToken:
        raise CredentialUndecryptable(row.id) from None
    if stale:
        await InternalDB(datasette.get_internal_database()).reencrypt_secret(
            row.id, old=token, new=box.rotate(token)
        )
    return data


@dataclass
class RotationResult:
    rotated: list[str] = field(default_factory=list)
    """Credential ids re-encrypted with the primary key."""
    current: list[str] = field(default_factory=list)
    """Already under the primary key (or changed concurrently)."""
    undecryptable: list[str] = field(default_factory=list)
    """No configured key decrypts these; left untouched."""


async def rotate_all_credentials(datasette: Datasette) -> RotationResult:
    """Re-encrypt every credential still under a non-primary key.

    After this, older keys can be dropped from ``encryption-key``, as long as
    ``undecryptable`` is empty.
    """
    box = require_box(datasette)
    idb = InternalDB(datasette.get_internal_database())
    result = RotationResult()
    for row in await idb.list_all():
        token = row.secret_encrypted
        try:
            if not box.needs_rotation(token):
                result.current.append(row.id)
                continue
            new = box.rotate(token)
        except InvalidToken:
            result.undecryptable.append(row.id)
            continue
        if await idb.reencrypt_secret(row.id, old=token, new=new):
            result.rotated.append(row.id)
        else:
            # Rewritten (or deleted) since we read it: its new secret was
            # encrypted with the primary key anyway.
            result.current.append(row.id)
    return result
