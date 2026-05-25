from __future__ import annotations

from conftest import _SimpleTTLCache


def test_simple_ttl_cache_prunes_expiry_index_on_lru_eviction():
    cache = _SimpleTTLCache(maxsize=2, ttl=60)

    cache["first"] = 1
    cache["second"] = 2
    cache["third"] = 3

    assert list(cache.keys()) == ["second", "third"]
    assert set(cache._expires_at) == {"second", "third"}
