"""Pydantic models for the JSON each page embeds as ``#pageData``.

``scripts/typegen-pagedata.py`` exports every model in ``__exports__`` as
JSON Schema, and ``just types-pagedata`` turns that into
``frontend/src/page_data/<Model>.types.ts``. Page data holds no secrets.
"""

from pydantic import BaseModel

from .routes.api import StatusResponse


class IndexPageData(BaseModel):
    """The ``/-/google-auth`` page (placeholder until ticket 14)."""

    status: StatusResponse


__exports__ = [IndexPageData]
