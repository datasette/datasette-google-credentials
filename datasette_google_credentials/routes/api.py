"""JSON API routes on the shared router (D13, tickets 12 and 15).

Handlers call the broker, service and admin layers, never ``InternalDB``,
and turn every ``GoogleCredentialsError`` into ``error_response``'s JSON. None may
escape to Datasette: core's telemetry middleware would record its message
(which can name a service account's ``client_email``) on the request span.
Ids an actor may not know about are 404s, exactly as in the broker (no
probing).

CSRF: Datasette (>=1.0a41) checks ``Sec-Fetch-Site`` / ``Origin`` on every
POST before any route runs, so there is no token to send. Same-origin
``fetch()`` and non-browser clients pass; cross-site browser requests get a
403. Bodies are capped at ``router.MAX_BODY_BYTES``.

``key_json`` is write-only: it is never echoed, and ``SecretStr`` keeps it
out of reprs. Unexpected errors while handling a key are logged by type and
stack only, never by message, which could quote the key.
"""

# No `from __future__ import annotations`: datasette-plugin-router inspects
# real annotation objects (Annotated[..., Body()], str) at decoration time.
import logging
import re
import traceback
from typing import Annotated

from datasette import Response
from datasette_plugin_router import Body
from pydantic import BaseModel, ConfigDict, SecretStr

from ..admin import actor_ids, actor_names, list_all_credentials
from ..config import encryption_configured, get_config, oauth_configured
from ..errors import GoogleCredentialsError, error_response
from ..models import (
    AdminCredentialInfo,
    CredentialInfo,
    DeleteResult,
    ListedCredential,
)
from ..oauth import redirect_uri
from ..permissions import can_add_service_account, can_admin, can_connect
from ..router import router
from ..service import (
    add_service_account,
    clean_label,
    delete,
    list_with_access,
    rename,
    rotate_service_account_key,
)

logger = logging.getLogger(__name__)

# --- Response models ----------------------------------------------------------


class CredentialListResponse(BaseModel):
    credentials: list[ListedCredential]


class AdminCredentialListResponse(BaseModel):
    credentials: list[AdminCredentialInfo]
    actor_names: dict[str, str]
    """Display names for the owner / created-by / last-used-by ids, from
    ``datasette.actors_from_ids()``. Ids without a name are absent: show the
    id."""


class ServiceAccountCreated(CredentialInfo):
    share_with_email: str
    """The service account's ``client_email``: share spreadsheets with it."""


class StatusResponse(BaseModel):
    """What the management page needs for its setup notices (ticket 14)."""

    encryption_configured: bool
    oauth_configured: bool
    internal_db_persistent: bool
    """False when Datasette runs without ``--internal``: credentials are
    lost on restart (D7)."""
    redirect_uri: str
    """The exact OAuth redirect URI to register in Google Cloud console."""
    can_connect: bool
    can_add_service_account: bool
    is_admin: bool


# --- Request models -----------------------------------------------------------


class AddServiceAccountRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    label: str = ""
    """Defaults to the key's ``client_email`` when empty."""
    key_json: SecretStr
    """The downloaded key file's contents, as a string."""


class RenameRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    label: str


class RotateKeyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    key_json: SecretStr


# --- Helpers ------------------------------------------------------------------

_SCOPE_SEPARATORS = re.compile(r"[,\s]+")


def _scopes_arg(request) -> list[str] | None:
    """``?scopes=a,b`` (commas or spaces; may repeat), or None if absent."""
    scopes = [
        scope
        for value in request.args.getlist("scopes")
        for scope in _SCOPE_SEPARATORS.split(value)
        if scope
    ]
    return scopes or None


def _key_error(what: str, ex: Exception) -> Response:
    """A 500 for an unexpected error while handling ``key_json``. Logs the
    exception type and stack (code lines only), never its message."""
    logger.error(
        "datasette-google-credentials: unexpected %s while %s\n%s",
        type(ex).__name__,
        what,
        "".join(traceback.format_tb(ex.__traceback__)),
    )
    return Response.json(
        {
            "ok": False,
            "error": f"Unexpected error while {what}",
            "code": "internal_error",
        },
        status=500,
    )


async def get_status(datasette, request) -> StatusResponse:
    """The status the ``/api/status`` endpoint returns; also for page data."""
    config = get_config(datasette)
    internal = datasette.get_internal_database()
    actor = request.actor
    signed_in = bool(actor) and actor.get("id") is not None
    return StatusResponse(
        encryption_configured=encryption_configured(config),
        oauth_configured=oauth_configured(config),
        # Without --internal, 1.0a41 uses a temp file deleted at exit
        # (is_temp_disk), not an in-memory database.
        internal_db_persistent=not (internal.is_memory or internal.is_temp_disk),
        redirect_uri=redirect_uri(datasette, request, config),
        can_connect=signed_in and await can_connect(datasette, actor),
        can_add_service_account=signed_in
        and await can_add_service_account(datasette, actor),
        is_admin=signed_in and await can_admin(datasette, actor),
    )


async def get_admin_credentials(
    datasette,
    request,
    *,
    owner: str | None = None,
    type: str | None = None,
    status: str | None = None,
) -> AdminCredentialListResponse:
    """The ``/api/admin/credentials`` listing; also the admin page's data.
    Raises ``CredentialForbidden`` unless the actor holds ``google-credentials-admin``."""
    credentials = await list_all_credentials(
        datasette, request.actor, owner=owner, type=type, status=status
    )
    return AdminCredentialListResponse(
        credentials=credentials,
        actor_names=await actor_names(datasette, actor_ids(credentials)),
    )


# --- Routes -------------------------------------------------------------------


@router.GET(r"/-/google-credentials/api/status$", output=StatusResponse)
async def api_status(datasette, request):
    try:
        status = await get_status(datasette, request)
    except GoogleCredentialsError as ex:
        return error_response(ex)
    return Response.json(status.model_dump())


@router.GET(r"/-/google-credentials/api/credentials$", output=CredentialListResponse)
async def api_credentials(datasette, request):
    # Anonymous actors get an empty list, not an error (as list_credentials).
    try:
        credentials = await list_with_access(
            datasette, request.actor, _scopes_arg(request)
        )
    except GoogleCredentialsError as ex:
        return error_response(ex)
    return Response.json(CredentialListResponse(credentials=credentials).model_dump())


@router.GET(
    r"/-/google-credentials/api/admin/credentials$", output=AdminCredentialListResponse
)
async def api_admin_credentials(datasette, request):
    try:
        listing = await get_admin_credentials(
            datasette,
            request,
            owner=request.args.get("owner") or None,
            type=request.args.get("type") or None,
            status=request.args.get("status") or None,
        )
    except GoogleCredentialsError as ex:
        return error_response(ex)
    return Response.json(listing.model_dump())


@router.POST(
    r"/-/google-credentials/api/service-accounts$", output=ServiceAccountCreated
)
async def api_add_service_account(
    datasette, request, body: Annotated[AddServiceAccountRequest, Body()]
):
    try:
        label = clean_label(body.label) if body.label.strip() else ""
        info = await add_service_account(
            datasette, request.actor, body.key_json.get_secret_value(), label
        )
    except GoogleCredentialsError as ex:
        return error_response(ex)
    except Exception as ex:
        return _key_error("adding a service account", ex)
    created = ServiceAccountCreated(
        **info.model_dump(), share_with_email=info.google_email or ""
    )
    # 200, not 201: the router's OpenAPI output only declares a 200 response,
    # which is what openapi-fetch types `data` from.
    return Response.json(created.model_dump())


@router.POST(
    r"/-/google-credentials/api/credentials/(?P<credential_id>[^/]+)/rename$",
    output=CredentialInfo,
)
async def api_rename(
    datasette, request, credential_id: str, body: Annotated[RenameRequest, Body()]
):
    try:
        info = await rename(datasette, request.actor, credential_id, body.label)
    except GoogleCredentialsError as ex:
        return error_response(ex)
    return Response.json(info.model_dump())


@router.POST(
    r"/-/google-credentials/api/credentials/(?P<credential_id>[^/]+)/rotate-key$",
    output=CredentialInfo,
)
async def api_rotate_key(
    datasette, request, credential_id: str, body: Annotated[RotateKeyRequest, Body()]
):
    try:
        info = await rotate_service_account_key(
            datasette, request.actor, credential_id, body.key_json.get_secret_value()
        )
    except GoogleCredentialsError as ex:
        return error_response(ex)
    except Exception as ex:
        return _key_error("rotating a service account key", ex)
    return Response.json(info.model_dump())


@router.POST(
    r"/-/google-credentials/api/credentials/(?P<credential_id>[^/]+)/delete$",
    output=DeleteResult,
)
async def api_delete(datasette, request, credential_id: str):
    try:
        result = await delete(datasette, request.actor, credential_id)
    except GoogleCredentialsError as ex:
        return error_response(ex)
    return Response.json(result.model_dump())
