"""Service-account keys: validate on intake, mint access tokens (D3, D15).

A pasted key file is parsed by ``parse_key``, which keeps only the fields we
need and **ignores ``token_uri``**. Honouring it (as sqlite-google-sheets
does) would let a crafted key make the server POST a signed JWT to any URL:
SSRF. The token endpoint always comes from plugin config
(``google_base_urls.oauth_token``, Google's unless overridden for tests), and
it is also the JWT ``aud`` (D21).

``add_service_account`` and ``rotate_service_account_key`` run a live token
exchange before saving anything, so a deleted or disabled key fails at the
form rather than at first use.

No error message here contains key material: parse errors name the field and
the problem, and Google's ``error_description`` carries no secrets.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import httpx2
import jwt
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from .config import REQUIRED_SCOPES, get_config
from .crypto import encrypt_secret, require_box
from .errors import (
    CredentialBroken,
    CredentialForbidden,
    CredentialNotFound,
    GoogleTokenError,
    InvalidServiceAccountKey,
)
from .events import (
    CredentialCreatedEvent,
    CredentialRotatedEvent,
    track_credential_event,
)
from .http import client, google_error
from .internal_db import InternalDB
from .models import CredentialInfo
from .permissions import (
    SA_EDIT,
    SA_USE,
    can_add_service_account,
    can_admin,
    sa_allowed_or_decoy,
    seed_manager,
)
from .telemetry import google_call
from .telemetry_registry import SCOPES_COUNT, TOKEN_MINT
from .token_cache import get_token_cache
from .tokens import Token

if TYPE_CHECKING:
    from datasette.app import Datasette

TYPE = "service_account"
JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer"
ASSERTION_LIFETIME = 3600
SERVICE_ACCOUNT_DOMAIN = ".gserviceaccount.com"
SHEETS_SCOPE = "https://www.googleapis.com/auth/spreadsheets"

# The fields kept, encrypted, in ``secret_encrypted`` (D15). ``client_id``
# is kept too but stored in the ``google_subject`` column: it isn't secret.
SECRET_FIELDS = ("client_email", "private_key", "private_key_id", "project_id")


@dataclass(frozen=True)
class ServiceAccountKey:
    """The parts of a key file we keep. ``private_key`` (PEM) is hidden from
    ``repr``."""

    client_email: str
    private_key: str = field(repr=False)
    private_key_id: str
    project_id: str
    client_id: str | None = None

    def to_secret(self) -> dict[str, str]:
        """The dict to encrypt into ``secret_encrypted`` (``SECRET_FIELDS``)."""
        return {name: getattr(self, name) for name in SECRET_FIELDS}

    @classmethod
    def from_secret(
        cls, secret: dict[str, Any], *, client_id: str | None = None
    ) -> ServiceAccountKey:
        """Rebuild a key from a decrypted ``secret_encrypted`` dict (plus the
        row's ``google_subject`` as ``client_id``)."""
        return cls(
            client_email=secret["client_email"],
            private_key=secret["private_key"],
            private_key_id=secret["private_key_id"],
            project_id=secret["project_id"],
            client_id=client_id,
        )


# --- Parsing ----------------------------------------------------------------


def _invalid(problem: str) -> InvalidServiceAccountKey:
    return InvalidServiceAccountKey(f"Invalid service account key: {problem}")


def _required_str(data: dict[str, Any], name: str) -> str:
    value = data.get(name)
    if not isinstance(value, str) or not value.strip():
        raise _invalid(f"'{name}' is missing or empty")
    return value


def _describe_type(value: object) -> str:
    # Echo the type only if it looks like a type name, so a pasted secret in
    # the wrong field can never come back in an error.
    if (
        isinstance(value, str)
        and 0 < len(value) <= 40
        and value.replace("_", "").isalnum()
    ):
        return f"type is '{value}'"
    return "type is missing or not a key type"


def parse_key(raw: str | bytes) -> ServiceAccountKey:
    """Validate a service-account key file and keep only what we need.

    Raises ``InvalidServiceAccountKey`` naming the problem. ``token_uri`` and
    every other unlisted field are ignored.
    """
    try:
        data = json.loads(raw)
    except (ValueError, TypeError):
        # json's message can quote the input; don't chain it.
        raise _invalid("not valid JSON") from None
    if not isinstance(data, dict):
        raise _invalid("expected a JSON object")
    if data.get("type") != TYPE:
        raise InvalidServiceAccountKey(
            f"Not a service account key: {_describe_type(data.get('type'))}"
        )

    client_email = _required_str(data, "client_email")
    if "@" not in client_email or not client_email.endswith(SERVICE_ACCOUNT_DOMAIN):
        raise _invalid(
            f"'client_email' must be a service account address ending in"
            f" {SERVICE_ACCOUNT_DOMAIN}"
        )
    private_key = _required_str(data, "private_key")
    try:
        loaded = load_pem_private_key(private_key.encode("utf-8"), password=None)
    except (ValueError, TypeError, UnsupportedAlgorithm):
        raise _invalid("'private_key' is not a PEM-encoded RSA private key") from None
    if not isinstance(loaded, rsa.RSAPrivateKey):
        raise _invalid("'private_key' is not an RSA key")
    private_key_id = _required_str(data, "private_key_id")
    project_id = _required_str(data, "project_id")

    client_id = data.get("client_id")
    return ServiceAccountKey(
        client_email=client_email,
        private_key=private_key,
        private_key_id=private_key_id,
        project_id=project_id,
        client_id=client_id if isinstance(client_id, str) and client_id else None,
    )


# --- Minting ----------------------------------------------------------------


def build_assertion(
    key: ServiceAccountKey, scopes: list[str], *, audience: str, now: int
) -> str:
    """The RS256 JWT-bearer assertion for ``key``."""
    return jwt.encode(
        {
            "iss": key.client_email,
            "sub": key.client_email,
            "aud": audience,
            "scope": " ".join(scopes),
            "iat": now,
            "exp": now + ASSERTION_LIFETIME,
        },
        key.private_key,
        algorithm="RS256",
        headers={"kid": key.private_key_id},
    )


async def mint_token(
    http: httpx2.AsyncClient,
    key: ServiceAccountKey,
    scopes: list[str],
    *,
    token_url: str,
) -> Token:
    """Exchange a signed JWT for an access token carrying ``scopes``.

    ``token_url`` is the configured ``google_base_urls.oauth_token``, never
    the key file's ``token_uri``; it is also the JWT audience.

    Raises ``CredentialBroken`` on ``invalid_grant`` (key deleted or
    disabled) and ``GoogleTokenError`` for any other failure.
    """
    if not scopes:
        raise ValueError("mint_token needs at least one scope")
    with google_call("mint", TOKEN_MINT) as call:
        call.set(SCOPES_COUNT, len(scopes))
        now = int(time.time())
        assertion = build_assertion(key, scopes, audience=token_url, now=now)
        try:
            response = await http.post(
                token_url, data={"grant_type": JWT_BEARER, "assertion": assertion}
            )
        except httpx2.HTTPError as ex:
            # The exception text may include the request; the class name is enough.
            raise GoogleTokenError(None, type(ex).__name__) from None
        call.response(response)

        if response.status_code != 200:
            error, description = google_error(response)
            if error == "invalid_grant":
                raise CredentialBroken(description or "invalid_grant")
            raise GoogleTokenError(response.status_code, error, description)
        try:
            body = response.json()
        except ValueError:
            body = None
        access_token = body.get("access_token") if isinstance(body, dict) else None
        if not isinstance(access_token, str) or not access_token:
            raise GoogleTokenError(200, "invalid_response", "no access_token in reply")
        expires_in = body.get("expires_in") if isinstance(body, dict) else None
        return Token.from_expires_in(
            access_token,
            expires_in if isinstance(expires_in, (int, float)) else None,
            scopes,
            now=now,
        )


async def mint_service_account_token(
    datasette: Datasette, key: ServiceAccountKey, scopes: list[str]
) -> Token:
    """``mint_token`` against the configured token URL with this instance's
    HTTP client. The broker's cache ``fetch`` calls this."""
    token_url = get_config(datasette).google_base_urls.oauth_token
    async with client(datasette) as http:
        return await mint_token(http, key, scopes, token_url=token_url)


def live_test_scopes(datasette: Datasette) -> list[str]:
    """Scopes for the pre-save test exchange: the configured API scopes
    (``openid``/``email`` are for OAuth sign-in only), else Sheets."""
    configured = [
        scope for scope in get_config(datasette).scopes if scope not in REQUIRED_SCOPES
    ]
    return configured or [SHEETS_SCOPE]


async def _live_test(datasette: Datasette, key: ServiceAccountKey) -> None:
    """Prove Google accepts the key before it is saved.

    ``invalid_grant`` becomes ``InvalidServiceAccountKey``: at intake it
    means "this key doesn't work", not "a stored credential broke".
    ``GoogleTokenError`` (5xx, network) propagates: it's not the key's fault.
    """
    try:
        await mint_service_account_token(datasette, key, live_test_scopes(datasette))
    except CredentialBroken as ex:
        raise InvalidServiceAccountKey(
            f"Google rejected this key: {ex.detail}"
        ) from None


# --- Add / rotate -----------------------------------------------------------


def _actor_id(actor: dict[str, Any] | None) -> str | None:
    if not actor or actor.get("id") is None:
        return None
    return str(actor["id"])


async def add_service_account(
    datasette: Datasette,
    actor: dict[str, Any] | None,
    raw_key: str | bytes,
    label: str,
) -> CredentialInfo:
    """Validate, live-test, encrypt and store a service-account key.

    The actor needs ``google-auth-add-service-account`` and becomes the
    owner and Manager. ``label`` defaults to the key's ``client_email``.

    Raises ``CredentialForbidden``, ``EncryptionNotConfigured``,
    ``InvalidServiceAccountKey`` or ``GoogleTokenError``; nothing is saved
    on any of them.
    """
    actor_id = _actor_id(actor)
    if actor_id is None or not await can_add_service_account(datasette, actor):
        raise CredentialForbidden("You don't have permission to add service accounts")
    require_box(datasette)
    key = parse_key(raw_key)
    await _live_test(datasette, key)

    idb = InternalDB(datasette.get_internal_database())
    row = await idb.insert(
        type=TYPE,
        label=label.strip() or key.client_email,
        owner_id=actor_id,
        created_by=actor_id,
        secret_encrypted=encrypt_secret(datasette, key.to_secret()),
        google_subject=key.client_id,
        google_email=key.client_email,
        scopes=[],
    )
    try:
        await seed_manager(datasette, row.id, actor_id)
    except Exception:
        # A credential nobody manages can't be shared or deleted from the UI.
        await idb.delete(row.id)
        raise
    await track_credential_event(datasette, CredentialCreatedEvent, row, actor)
    return CredentialInfo.from_row(row, actor)


async def rotate_service_account_key(
    datasette: Datasette,
    actor: dict[str, Any] | None,
    credential_id: str,
    raw_key: str | bytes,
) -> CredentialInfo:
    """Replace a service account's key with a new key for the same account.

    Needs ``google-service-account-edit``. The new key must have the same
    ``client_email``: changing identity would silently change which sheets
    the credential can reach. Live-tests the key, re-encrypts, clears a
    broken status and evicts cached tokens.

    Raises ``CredentialNotFound`` if the credential doesn't exist, isn't a
    service account, or the actor can't see it (no ID probing, D11);
    ``CredentialForbidden`` if they can see it but not edit it;
    otherwise as ``add_service_account``.
    """
    idb = InternalDB(datasette.get_internal_database())
    found = await idb.get(credential_id)
    actor_id = _actor_id(actor)
    if actor_id is None:
        raise CredentialNotFound(credential_id)
    # An unknown id or another type runs the same checks as an unshared
    # service account, against a decoy id (ticket 24), then is NotFound.
    row = found if found is not None and found.type == TYPE else None
    editable = await sa_allowed_or_decoy(datasette, SA_EDIT, actor, row)
    if row is None or not editable:
        if (
            await sa_allowed_or_decoy(datasette, SA_USE, actor, row)
            or await can_admin(datasette, actor)
        ) and row is not None:
            raise CredentialForbidden(
                "You don't have permission to rotate this service account's key"
            )
        raise CredentialNotFound(credential_id)
    require_box(datasette)
    key = parse_key(raw_key)
    if key.client_email != row.google_email:
        raise InvalidServiceAccountKey(
            "This key is for a different service account: the new key's"
            " client_email must match the existing one"
            f" ({row.google_email}). Add it as a new service account instead."
        )
    await _live_test(datasette, key)

    if not await idb.update_secret(
        row.id, encrypt_secret(datasette, key.to_secret()), actor_id=actor_id
    ):
        raise CredentialNotFound(credential_id)
    get_token_cache(datasette).evict(row.id)
    await track_credential_event(datasette, CredentialRotatedEvent, row, actor)
    updated = await idb.get(row.id)
    if updated is None:
        raise CredentialNotFound(credential_id)
    return CredentialInfo.from_row(updated, actor)
