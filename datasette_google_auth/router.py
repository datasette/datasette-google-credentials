"""The shared router every module in ``routes/`` registers on.

Every view it hands to Datasette caps the request body at
``MAX_BODY_BYTES``, well under Datasette's own ``max_post_body_bytes``
(2 MB by default). The largest legitimate body is a pasted service-account
key file (about 2.4 KB). datasette-plugin-router reads and parses a ``Body()``
before the handler runs, so the cap has to wrap the router's view rather than
live in a handler.
"""

from __future__ import annotations

import functools
from collections.abc import Callable
from typing import Any

from datasette import Response
from datasette.utils.asgi import PayloadTooLarge
from datasette_plugin_router import Router

MAX_BODY_BYTES = 16 * 1024


def limit_body(view: Callable[..., Any]) -> Callable[..., Any]:
    """Wrap a router view so ``request.post_body()`` reads at most
    ``MAX_BODY_BYTES``; a larger body gets a JSON 413 in ``error_response``'s
    shape. Datasette's own setting still wins if it is lower."""

    @functools.wraps(view)
    async def limited(request, datasette=None, scope=None, receive=None, send=None):
        current = request.max_post_body_bytes
        request.max_post_body_bytes = (
            min(current, MAX_BODY_BYTES) if current else MAX_BODY_BYTES
        )
        try:
            return await view(
                request, datasette=datasette, scope=scope, receive=receive, send=send
            )
        except PayloadTooLarge:
            return Response.json(
                {
                    "ok": False,
                    "error": f"Request body is larger than {MAX_BODY_BYTES} bytes",
                    "code": "payload_too_large",
                },
                status=413,
            )

    return limited


class GoogleAuthRouter(Router):
    """A ``Router`` whose views all go through ``limit_body``."""

    def routes(self) -> list[tuple[str, Callable[..., Any]]]:
        return [(path, limit_body(view)) for path, view in super().routes()]


# The one Router every module in routes/ registers on.
router = GoogleAuthRouter(title="datasette-google-auth")
