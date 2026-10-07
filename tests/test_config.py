import base64
import logging

import httpx2
import pytest
from datasette.app import Datasette
from datasette.utils import StartupError

from datasette_google_credentials.config import (
    Config,
    encryption_configured,
    get_config,
    oauth_configured,
)
from datasette_google_credentials.http import client, set_transport

# Obviously fake values; the assertions check they never leak. Keys must be
# well-formed Fernet keys (32 url-safe base64 bytes) or startup rejects them.
FAKE_KEY = base64.urlsafe_b64encode(b"fake-encryption-key-for-tests-01").decode()
FAKE_OLD_KEY = base64.urlsafe_b64encode(b"fake-encryption-key-for-tests-02").decode()
FAKE_SECRET = "fake-client-secret-CCCCCCCC"


def make_datasette(plugin_config):
    return Datasette(
        memory=True,
        config={"plugins": {"datasette-google-credentials": plugin_config}},
    )


async def started(plugin_config):
    datasette = make_datasette(plugin_config)
    await datasette.invoke_startup()
    return datasette


@pytest.mark.asyncio
async def test_defaults():
    datasette = Datasette(memory=True)
    await datasette.invoke_startup()
    config = get_config(datasette)
    assert config.encryption_key is None
    assert config.client_id is None
    assert config.client_secret is None
    assert config.redirect_uri is None
    assert config.scopes == [
        "openid",
        "email",
        "https://www.googleapis.com/auth/spreadsheets",
    ]
    assert config.google_base_urls.oauth_token == "https://oauth2.googleapis.com/token"
    assert (
        config.google_base_urls.oauth_authorize
        == "https://accounts.google.com/o/oauth2/v2/auth"
    )
    assert config.google_base_urls.oauth_revoke == (
        "https://oauth2.googleapis.com/revoke"
    )
    assert config.google_base_urls.userinfo == (
        "https://openidconnect.googleapis.com/v1/userinfo"
    )
    assert not oauth_configured(config)
    assert not encryption_configured(config)


@pytest.mark.asyncio
async def test_full_config():
    datasette = await started(
        {
            "encryption-key": FAKE_KEY,
            "client_id": "id.apps.googleusercontent.com",
            "client_secret": FAKE_SECRET,
            "redirect_uri": "https://example.com/-/google-credentials/oauth/callback",
            "google_base_urls": {"oauth_token": "http://mock/token"},
        }
    )
    config = get_config(datasette)
    assert config.encryption_keys == [FAKE_KEY]
    assert encryption_configured(config)
    assert oauth_configured(config)
    assert (
        config.redirect_uri == "https://example.com/-/google-credentials/oauth/callback"
    )
    assert config.google_base_urls.oauth_token == "http://mock/token"
    # Unspecified base URLs keep their defaults
    assert config.google_base_urls.oauth_revoke == (
        "https://oauth2.googleapis.com/revoke"
    )


@pytest.mark.parametrize(
    "plugin_config,configured",
    [
        ({"client_id": "id"}, False),
        ({"client_secret": FAKE_SECRET}, False),
        ({"client_id": "id", "client_secret": FAKE_SECRET}, True),
        ({"client_id": "", "client_secret": FAKE_SECRET}, False),
    ],
)
def test_oauth_configured(plugin_config, configured):
    assert oauth_configured(Config.model_validate(plugin_config)) is configured


def test_list_of_keys_accepted():
    config = Config.model_validate({"encryption-key": [FAKE_KEY, FAKE_OLD_KEY]})
    assert config.encryption_keys == [FAKE_KEY, FAKE_OLD_KEY]
    assert encryption_configured(config)


@pytest.mark.parametrize("value", [None, "", []])
def test_empty_encryption_key_is_not_configured(value):
    assert not encryption_configured(Config.model_validate({"encryption-key": value}))


@pytest.mark.asyncio
async def test_env_resolution(monkeypatch):
    monkeypatch.setenv("TEST_GOOGLE_CREDENTIALS_KEY", FAKE_KEY)
    monkeypatch.setenv("TEST_GOOGLE_CREDENTIALS_OLD_KEY", FAKE_OLD_KEY)
    monkeypatch.setenv("TEST_GOOGLE_CLIENT_SECRET", FAKE_SECRET)
    datasette = await started(
        {
            "encryption-key": [
                {"$env": "TEST_GOOGLE_CREDENTIALS_KEY"},
                {"$env": "TEST_GOOGLE_CREDENTIALS_OLD_KEY"},
            ],
            "client_id": "id",
            "client_secret": {"$env": "TEST_GOOGLE_CLIENT_SECRET"},
        }
    )
    config = get_config(datasette)
    assert config.encryption_keys == [FAKE_KEY, FAKE_OLD_KEY]
    assert config.client_secret == FAKE_SECRET


@pytest.mark.asyncio
async def test_unset_env_var_means_not_configured(monkeypatch):
    monkeypatch.delenv("TEST_GOOGLE_CREDENTIALS_KEY", raising=False)
    datasette = await started(
        {"encryption-key": {"$env": "TEST_GOOGLE_CREDENTIALS_KEY"}}
    )
    assert not encryption_configured(get_config(datasette))


@pytest.mark.asyncio
async def test_file_resolution(tmp_path):
    key_file = tmp_path / "key.txt"
    key_file.write_text(FAKE_KEY)
    datasette = await started({"encryption-key": {"$file": str(key_file)}})
    assert get_config(datasette).encryption_keys == [FAKE_KEY]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "plugin_config,bad_key",
    [
        ({"client_secert": "x"}, "client_secert"),
        ({"encryption_key": "x"}, "encryption_key"),
        ({"google_base_urls": {"oauth_tokens": "x"}}, "google_base_urls.oauth_tokens"),
        ({"scopes": "openid email"}, "scopes"),
    ],
)
async def test_bad_config_fails_startup(plugin_config, bad_key):
    datasette = make_datasette(plugin_config)
    with pytest.raises(StartupError) as excinfo:
        await datasette.invoke_startup()
    message = str(excinfo.value)
    assert "datasette-google-credentials" in message
    assert f"  {bad_key}:" in message


@pytest.mark.asyncio
async def test_startup_error_never_echoes_secrets(monkeypatch):
    # A list with an unset env var yields None inside the list: invalid. The
    # error must name the field without echoing the other (valid) key.
    monkeypatch.setenv("TEST_GOOGLE_CREDENTIALS_KEY", FAKE_KEY)
    monkeypatch.delenv("TEST_GOOGLE_CREDENTIALS_MISSING", raising=False)
    datasette = make_datasette(
        {
            "encryption-key": [
                {"$env": "TEST_GOOGLE_CREDENTIALS_KEY"},
                {"$env": "TEST_GOOGLE_CREDENTIALS_MISSING"},
            ],
            "client_secret": FAKE_SECRET,
            "unexpected": FAKE_SECRET,
        }
    )
    with pytest.raises(StartupError) as excinfo:
        await datasette.invoke_startup()
    message = str(excinfo.value)
    assert "encryption-key" in message
    assert "unexpected" in message
    assert FAKE_KEY not in message
    assert FAKE_SECRET not in message
    # Chained exceptions would carry pydantic's own rendering of the input
    assert excinfo.value.__cause__ is None
    assert excinfo.value.__suppress_context__


@pytest.mark.parametrize(
    "scopes,expected",
    [
        (
            ["https://www.googleapis.com/auth/spreadsheets.readonly"],
            [
                "openid",
                "email",
                "https://www.googleapis.com/auth/spreadsheets.readonly",
            ],
        ),
        (["email", "extra"], ["openid", "email", "extra"]),
        (["extra", "openid", "email"], ["extra", "openid", "email"]),
    ],
)
def test_openid_and_email_auto_added(scopes, expected, caplog):
    with caplog.at_level(logging.INFO, logger="datasette_google_credentials.config"):
        config = Config.model_validate({"scopes": scopes})
    assert config.scopes == expected
    added = [s for s in ("openid", "email") if s not in scopes]
    if added:
        assert "adding required OAuth scopes" in caplog.text
        for scope in added:
            assert scope in caplog.text
    else:
        assert caplog.text == ""


@pytest.mark.asyncio
async def test_config_page_redacts_secrets(monkeypatch):
    monkeypatch.setenv("TEST_GOOGLE_CLIENT_SECRET", FAKE_SECRET)
    for plugin_config in (
        # Literal values
        {
            "encryption-key": FAKE_KEY,
            "client_id": "visible-client-id",
            "client_secret": FAKE_SECRET,
        },
        # List of keys, and $env
        {
            "encryption-key": [FAKE_KEY, FAKE_OLD_KEY],
            "client_id": "visible-client-id",
            "client_secret": {"$env": "TEST_GOOGLE_CLIENT_SECRET"},
        },
    ):
        datasette = await started(plugin_config)
        response = await datasette.client.get("/-/config.json")
        assert response.status_code == 200
        shown = response.json()["plugins"]["datasette-google-credentials"]
        assert shown["encryption-key"] == "***"
        assert shown["client_secret"] == "***"
        assert shown["client_id"] == "visible-client-id"
        for path in ("/-/config.json", "/-/config"):
            text = (await datasette.client.get(path)).text
            for secret in (FAKE_KEY, FAKE_OLD_KEY, FAKE_SECRET):
                assert secret not in text


@pytest.mark.asyncio
async def test_http_client_uses_injected_transport():
    datasette = Datasette(memory=True)
    seen = []

    def handler(request):
        seen.append(str(request.url))
        return httpx2.Response(200, json={"ok": True})

    set_transport(datasette, httpx2.MockTransport(handler))
    async with client(datasette) as http:
        response = await http.get("https://oauth2.googleapis.com/token")
    assert response.json() == {"ok": True}
    assert seen == ["https://oauth2.googleapis.com/token"]
    assert http.follow_redirects is False

    # Resetting drops the override (not exercised against the network)
    set_transport(datasette, None)
    assert datasette._google_credentials_transport is None
