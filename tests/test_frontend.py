"""The frontend scaffold (ticket 13): base template, Vite entry, page data.

datasette-vite runs in dev mode here (``dev_ports``), so the page renders
without a built ``manifest.json`` and nothing contacts the Vite server.
"""

import json
import re

import pytest
from cryptography.fernet import Fernet

from datasette_google_auth.page_data import IndexPageData
from datasette_google_auth.permissions import ADD_SERVICE_ACCOUNT, ADMIN, CONNECT

DEV_PORT = 5187


async def make_datasette(mock_google):
    datasette = mock_google.datasette(
        plugin_config={"encryption-key": Fernet.generate_key().decode()},
        config={
            "permissions": {
                CONNECT: {"id": "alice"},
                ADD_SERVICE_ACCOUNT: {"id": "alice"},
                ADMIN: {"id": "admin"},
            },
            "plugins": {
                "datasette-vite": {
                    "dev_ports": {"datasette_google_auth": DEV_PORT},
                }
            },
        },
    )
    await datasette.invoke_startup()
    return datasette


def cookies(datasette, actor):
    return {"ds_actor": datasette.client.actor_cookie(actor)}


@pytest.mark.asyncio
@pytest.mark.parametrize("actor", [{"id": "alice"}, {"id": "admin"}])
async def test_index_page_renders_vite_entry_and_page_data(mock_google, actor):
    datasette = await make_datasette(mock_google)
    response = await datasette.client.get(
        "/-/google-auth", cookies=cookies(datasette, actor)
    )
    assert response.status_code == 200
    html = response.text
    assert f'src="http://localhost:{DEV_PORT}/@vite/client"' in html
    assert f'src="http://localhost:{DEV_PORT}/src/pages/index/index.ts"' in html
    assert '<div id="app-root"></div>' in html
    match = re.search(
        r'<script type="application/json" id="pageData">(.*?)</script>',
        html,
        re.DOTALL,
    )
    assert match
    page_data = IndexPageData.model_validate(json.loads(match.group(1)))
    assert page_data.status.encryption_configured is True
    assert page_data.status.is_admin is (actor["id"] == "admin")


@pytest.mark.asyncio
@pytest.mark.parametrize("actor", [None, {"id": "nobody"}])
async def test_index_page_forbidden_without_any_google_auth_permission(
    mock_google, actor
):
    datasette = await make_datasette(mock_google)
    response = await datasette.client.get(
        "/-/google-auth", cookies=cookies(datasette, actor) if actor else {}
    )
    assert response.status_code == 403
    assert 'id="pageData"' not in response.text


@pytest.mark.asyncio
async def test_oauth_routes_still_distinct_from_page(mock_google):
    # The page's `$`-anchored route must not swallow /-/google-auth/...
    datasette = await make_datasette(mock_google)
    response = await datasette.client.get(
        "/-/google-auth/oauth/callback", cookies=cookies(datasette, {"id": "alice"})
    )
    assert 'id="pageData"' not in response.text
