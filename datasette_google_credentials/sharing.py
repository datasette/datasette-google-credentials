"""The ``<datasette-acl-share-dialog>`` for service accounts (D13, ticket 14).

datasette-acl-share registers no site-wide assets: a host returns
``datasette_share_assets()`` from its own ``extra_js_urls`` /
``extra_css_urls`` hooks, gated on its pages. Here that is the management
page only (``is_management_page``). Closest template:
``datasette-drive/datasette_drive/sharing.py``.

The bundle is built into datasette-acl-share's package (gitignored there).
Without a built ``manifest.json`` (and without a datasette-vite dev port for
it) datasette-vite raises ``ValueError``; ``share_assets`` returns None
instead, so the page still renders, just without Share buttons.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from datasette_acl_share import datasette_share_assets, share_capabilities

if TYPE_CHECKING:
    from datasette.app import Datasette

logger = logging.getLogger(__name__)

#: The one template every page renders (``routes/pages.py``).
TEMPLATE = "google_credentials_base.html"
#: The management page's path.
PAGE_PATH = "/-/google-credentials"

_warned = False


def is_management_page(template: str | None, request: Any) -> bool:
    """True while rendering the management page itself: not its 403 page
    (another template), nor another page on the same template (ticket 15's
    admin view)."""
    return (
        template == TEMPLATE
        and request is not None
        and request.path.rstrip("/") == PAGE_PATH
    )


def share_assets(datasette: Datasette) -> dict[str, list] | None:
    """``{"js": [...], "css": [...]}`` for the share dialog, or None if its
    bundle isn't built (warned once per process)."""
    global _warned
    try:
        return datasette_share_assets(datasette)
    except ValueError:
        if not _warned:
            _warned = True
            logger.warning(
                "datasette-google-credentials: datasette-acl-share's frontend isn't"
                " built (no manifest.json), so service accounts can't be"
                " shared from the Google accounts page"
            )
        return None


def share_features() -> str:
    """The dialog's ``features`` attribute, e.g. ``"groups,public"``: only
    the sections the installed backends support (no People search without
    datasette-user-profiles)."""
    return ",".join(name for name, ok in share_capabilities().items() if ok)
