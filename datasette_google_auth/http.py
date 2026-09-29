"""The one place outbound HTTP clients are built.

Every call to Google goes through ``client(datasette)``. Tests inject a
transport (for example an ``httpx2.ASGITransport`` wrapping the mock Google
app) with ``set_transport()``, so they never need to touch plugin config for
this and can never reach the real network by accident.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import httpx2

if TYPE_CHECKING:
    from datasette.app import Datasette

_TRANSPORT_ATTR = "_google_auth_transport"

TIMEOUT = httpx2.Timeout(10.0)


def set_transport(
    datasette: Datasette, transport: httpx2.AsyncBaseTransport | None
) -> None:
    """Route this instance's outbound HTTP through ``transport`` (``None`` resets)."""
    setattr(datasette, _TRANSPORT_ATTR, transport)


def client(datasette: Datasette) -> httpx2.AsyncClient:
    """A new AsyncClient; use as ``async with client(datasette) as c:``.

    Redirects are not followed, so a response can't bounce a request (and its
    credentials) to another host.
    """
    transport = getattr(datasette, _TRANSPORT_ATTR, None)
    return httpx2.AsyncClient(
        transport=transport, timeout=TIMEOUT, follow_redirects=False
    )


# Google's error_description is safe to show, but cap it anyway.
MAX_ERROR_DETAIL = 300


def google_error(response: httpx2.Response) -> tuple[str | None, str | None]:
    """Google's OAuth ``error`` and ``error_description`` from a reply body,
    each ``None`` if absent or not a string. The description (which carries
    no secrets) is capped at ``MAX_ERROR_DETAIL`` characters."""
    try:
        body = response.json()
    except ValueError:
        return None, None
    if not isinstance(body, dict):
        return None, None
    error, description = body.get("error"), body.get("error_description")
    return (
        error if isinstance(error, str) else None,
        description[:MAX_ERROR_DETAIL] if isinstance(description, str) else None,
    )
