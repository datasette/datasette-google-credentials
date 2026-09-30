"""Pydantic models for the JSON each page embeds as ``#pageData``.

``scripts/typegen-pagedata.py`` exports every model in ``__exports__`` as
JSON Schema, and ``just types-pagedata`` turns that into
``frontend/src/page_data/<Model>.types.ts``. Page data holds no secrets.
"""

from pydantic import BaseModel

from .models import AdminCredentialInfo, ListedCredential
from .routes.api import StatusResponse


class ShareDialog(BaseModel):
    """Settings for ``<datasette-acl-share-dialog>`` on service accounts."""

    features: str
    """The dialog's ``features`` attribute (``sharing.share_features()``)."""


class IndexPageData(BaseModel):
    """The ``/-/google-auth`` management page (ticket 14)."""

    status: StatusResponse
    credentials: list[ListedCredential]
    """The first render of ``GET /api/credentials``; the page refetches it
    after every change."""
    actor_id: str
    """For the share dialog's "(you)" marker."""
    connect_url: str
    """Starts Connect Google (and Reconnect) and comes back to this page."""
    share: ShareDialog | None
    """None when datasette-acl-share's bundle isn't built: no Share buttons."""
    admin_url: str | None
    """The "All credentials" admin page, for ``google-auth-admin`` holders
    only (None otherwise)."""


class AdminPageData(BaseModel):
    """The ``/-/google-auth/admin`` "All credentials" page (ticket 15).
    Information only: nothing here lets the admin use a credential (D6)."""

    status: StatusResponse
    credentials: list[AdminCredentialInfo]
    """The first render of ``GET /api/admin/credentials`` (unfiltered); the
    page filters it in the browser and refetches it after a delete."""
    actor_names: dict[str, str]
    """Display names for actor ids (``actors_from_ids``); absent ids show as
    themselves."""
    manage_url: str
    """The ``/-/google-auth`` management page, where admins manage their own
    credentials."""


__exports__ = [IndexPageData, AdminPageData]
