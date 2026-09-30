"""Public, secret-free views of credentials (D11).

``CredentialInfo`` is what consumers, API responses and the UI see. It is
built from a ``CredentialRow`` and never carries ``secret_encrypted`` or
anything derived from it.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel

from .internal_db import CredentialRow


class CredentialInfo(BaseModel):
    """One credential as an actor sees it. Never contains secrets."""

    id: str
    type: str
    label: str
    google_email: str | None
    scopes: list[str]
    """Granted scopes (OAuth). Always empty for service accounts, which mint
    whatever scopes are requested."""
    status: str
    status_detail: str | None
    is_owner: bool

    @classmethod
    def from_row(
        cls, row: CredentialRow, actor: dict[str, Any] | None
    ) -> CredentialInfo:
        actor_id = (actor or {}).get("id")
        return cls(
            id=row.id,
            type=row.type,
            label=row.label,
            google_email=row.google_email,
            scopes=list(row.scopes),
            status=row.status,
            status_detail=row.status_detail,
            is_owner=actor_id is not None and str(actor_id) == row.owner_id,
        )


class AdminCredentialInfo(CredentialInfo):
    """One credential as a ``google-auth-admin`` sees it in the "All
    credentials" view (ticket 15): ``CredentialInfo`` plus who owns it and
    who used it last. Information only: it never grants use (D6)."""

    owner_id: str
    created_by: str
    last_used_at: str | None
    last_used_by: str | None

    @classmethod
    def from_row(
        cls, row: CredentialRow, actor: dict[str, Any] | None
    ) -> AdminCredentialInfo:
        return cls(
            **CredentialInfo.from_row(row, actor).model_dump(),
            owner_id=row.owner_id,
            created_by=row.created_by,
            last_used_at=row.last_used_at,
            last_used_by=row.last_used_by,
        )


class DeleteResult(BaseModel):
    """What ``service.delete()`` did, for the UI to report. No secrets.

    OAuth: ``revoked`` says whether Google confirmed revoking the refresh
    token; if not, ``revoke_error`` says why and the user should remove
    access at myaccount.google.com/permissions. The row is deleted either
    way.

    Service account: the key still exists at Google, so the UI should say
    "Also delete key ``private_key_id`` in the Cloud console", linking to
    ``cloud_console_url``. Those fields are ``None`` if the stored key
    couldn't be decrypted.
    """

    id: str
    type: str
    revoked: bool | None = None
    revoke_error: str | None = None
    client_email: str | None = None
    private_key_id: str | None = None
    project_id: str | None = None
    cloud_console_url: str | None = None
