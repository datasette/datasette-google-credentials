import asyncio

import pytest
from datasette.app import Datasette

from datasette_google_auth.internal_db import CredentialRow
from datasette_google_auth.token_cache import (
    EXPIRY_SKEW,
    CacheKey,
    TokenCache,
    get_token_cache,
)
from datasette_google_auth.tokens import DEFAULT_TOKEN_LIFETIME, Token

READ = frozenset({"https://www.googleapis.com/auth/spreadsheets.readonly"})
WRITE = frozenset({"https://www.googleapis.com/auth/spreadsheets"})
T0 = 1_800_000_000.0


class FakeClock:
    def __init__(self, now=T0):
        self.now = now

    def __call__(self):
        return self.now


class Fetcher:
    """Counts calls; each call returns a new token valid for ``lifetime``."""

    def __init__(self, clock, lifetime=3600.0, scopes=READ):
        self.clock = clock
        self.lifetime = lifetime
        self.scopes = scopes
        self.calls = 0

    async def __call__(self):
        self.calls += 1
        # Yield so concurrent callers really overlap.
        await asyncio.sleep(0)
        return Token(
            access_token=f"ya29.token-{self.calls}",
            expires_at=self.clock() + self.lifetime,
            scopes=self.scopes,
        )


def key(credential_id="cred1", version="v1", scopes=READ):
    return CacheKey(credential_id, version, scopes)


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def cache(clock):
    return TokenCache(clock=clock)


@pytest.mark.asyncio
async def test_hit_within_window(cache, clock):
    fetch = Fetcher(clock)
    first = await cache.get_or_fetch(key(), fetch)
    clock.now += 3600 - EXPIRY_SKEW - 1  # 61s left
    second = await cache.get_or_fetch(key(), fetch)
    assert second is first
    assert fetch.calls == 1


@pytest.mark.asyncio
async def test_refetch_inside_skew(cache, clock):
    fetch = Fetcher(clock)
    first = await cache.get_or_fetch(key(), fetch)
    clock.now += 3600 - EXPIRY_SKEW  # exactly 60s left: not reused
    second = await cache.get_or_fetch(key(), fetch)
    assert fetch.calls == 2
    assert second.access_token != first.access_token
    # The refreshed token is now cached.
    assert await cache.get_or_fetch(key(), fetch) is second
    assert fetch.calls == 2


@pytest.mark.asyncio
async def test_concurrent_callers_fetch_once(cache, clock):
    fetch = Fetcher(clock)
    tokens = await asyncio.gather(
        *(cache.get_or_fetch(key(), fetch) for _ in range(10))
    )
    assert fetch.calls == 1
    assert len({id(t) for t in tokens}) == 1


@pytest.mark.asyncio
async def test_failure_not_cached(cache, clock):
    calls = 0

    async def failing():
        nonlocal calls
        calls += 1
        raise RuntimeError("token endpoint down")

    with pytest.raises(RuntimeError):
        await cache.get_or_fetch(key(), failing)
    fetch = Fetcher(clock)
    token = await cache.get_or_fetch(key(), fetch)
    assert calls == 1
    assert fetch.calls == 1
    assert token.access_token == "ya29.token-1"


@pytest.mark.asyncio
async def test_concurrent_failure_retried_by_waiters(cache, clock):
    # The first caller fails; a waiter queued on the lock fetches again
    # rather than getting a cached failure.
    results = []

    async def fails_then_works():
        results.append(None)
        await asyncio.sleep(0)
        if len(results) == 1:
            raise RuntimeError("boom")
        return Token("ya29.ok", clock() + 3600, READ)

    outcomes = await asyncio.gather(
        cache.get_or_fetch(key(), fails_then_works),
        cache.get_or_fetch(key(), fails_then_works),
        return_exceptions=True,
    )
    assert isinstance(outcomes[0], RuntimeError)
    assert isinstance(outcomes[1], Token)
    assert len(results) == 2


@pytest.mark.asyncio
async def test_evict_clears_every_scope_variant(cache, clock):
    fetch = Fetcher(clock)
    await cache.get_or_fetch(key(scopes=READ), fetch)
    await cache.get_or_fetch(key(scopes=WRITE), fetch)
    await cache.get_or_fetch(key(version="v0", scopes=READ), fetch)
    other = await cache.get_or_fetch(key(credential_id="cred2"), fetch)
    assert fetch.calls == 4

    cache.evict("cred1")
    assert len(cache) == 1

    await cache.get_or_fetch(key(scopes=READ), fetch)
    await cache.get_or_fetch(key(scopes=WRITE), fetch)
    assert fetch.calls == 6
    # Other credentials are untouched.
    assert await cache.get_or_fetch(key(credential_id="cred2"), fetch) is other
    assert fetch.calls == 6


@pytest.mark.asyncio
async def test_evict_during_fetch_does_not_cache_result(cache, clock):
    fetch = Fetcher(clock)
    started = asyncio.Event()
    release = asyncio.Event()

    async def slow_fetch():
        started.set()
        await release.wait()
        return await fetch()

    task = asyncio.create_task(cache.get_or_fetch(key(), slow_fetch))
    await started.wait()
    cache.evict("cred1")
    release.set()
    await task
    await cache.get_or_fetch(key(), fetch)
    assert fetch.calls == 2


@pytest.mark.asyncio
async def test_changed_secret_version_misses(cache, clock):
    fetch = Fetcher(clock)
    first = await cache.get_or_fetch(key(version="v1"), fetch)
    second = await cache.get_or_fetch(key(version="v2"), fetch)
    assert fetch.calls == 2
    assert second is not first


@pytest.mark.asyncio
async def test_lru_bound(clock):
    cache = TokenCache(clock=clock, max_entries=3)
    fetch = Fetcher(clock)
    for i in range(3):
        await cache.get_or_fetch(key(credential_id=f"c{i}"), fetch)
    # Touch c0 so c1 is the least recently used.
    await cache.get_or_fetch(key(credential_id="c0"), fetch)
    assert fetch.calls == 3

    await cache.get_or_fetch(key(credential_id="c3"), fetch)
    assert len(cache) == 3
    assert fetch.calls == 4

    # c0, c2, c3 still cached; c1 was dropped.
    for name in ("c0", "c2", "c3"):
        await cache.get_or_fetch(key(credential_id=name), fetch)
    assert fetch.calls == 4
    await cache.get_or_fetch(key(credential_id="c1"), fetch)
    assert fetch.calls == 5
    assert len(cache) == 3


def test_max_entries_must_be_positive():
    with pytest.raises(ValueError):
        TokenCache(max_entries=0)


def test_token_repr_hides_access_token():
    token = Token("ya29.super-secret", T0, READ)
    assert "ya29" not in repr(token)
    assert "ya29" not in str(token)
    assert "expires_at" in repr(token)


def test_token_from_expires_in():
    token = Token.from_expires_in("ya29.x", 1800, ["a", "b"], now=T0)
    assert token.expires_at == T0 + 1800
    assert token.scopes == frozenset({"a", "b"})
    # Google omitted expires_in: assume an hour.
    token = Token.from_expires_in("ya29.x", None, READ, now=T0)
    assert token.expires_at == T0 + DEFAULT_TOKEN_LIFETIME == T0 + 3600


def row(**overrides):
    values = {
        "id": "cred1",
        "type": "service_account",
        "label": "SA",
        "owner_id": "alice",
        "google_subject": None,
        "google_email": None,
        "scopes": "[]",
        "secret_encrypted": b"ciphertext",
        "status": "ok",
        "status_detail": None,
        "last_used_at": None,
        "last_used_by": None,
        "created_at": "2026-09-29T10:00:00.000Z",
        "created_by": "alice",
        "updated_at": None,
        "updated_by": None,
    }
    values.update(overrides)
    return CredentialRow.model_validate(values)


def test_cache_key_for_row():
    fresh = CacheKey.for_row(row(), ["b", "a"])
    assert fresh == CacheKey("cred1", "2026-09-29T10:00:00.000Z", frozenset("ab"))
    rotated = CacheKey.for_row(row(updated_at="2026-09-29T11:00:00.000Z"), "ab")
    assert rotated.secret_version == "2026-09-29T11:00:00.000Z"
    assert rotated != fresh
    # The key never carries the secret.
    assert "ciphertext" not in repr(fresh)


@pytest.mark.asyncio
async def test_get_token_cache_created_at_startup():
    datasette = Datasette(memory=True)
    await datasette.invoke_startup()
    cache = get_token_cache(datasette)
    assert isinstance(cache, TokenCache)
    assert get_token_cache(datasette) is cache
    # Per instance.
    assert get_token_cache(Datasette(memory=True)) is not cache
