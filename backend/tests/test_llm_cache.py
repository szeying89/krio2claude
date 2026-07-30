import stat

from app.services.llm.cache import ContentAddressedCache, compute_cache_key


def test_cache_key_deterministic_for_same_inputs():
    key1 = compute_cache_key(prompt="p", model="m", params={"temperature": 0.0})
    key2 = compute_cache_key(prompt="p", model="m", params={"temperature": 0.0})
    assert key1 == key2


def test_cache_key_differs_when_prompt_differs():
    key1 = compute_cache_key(prompt="p1", model="m", params={})
    key2 = compute_cache_key(prompt="p2", model="m", params={})
    assert key1 != key2


def test_cache_key_differs_when_kb_snapshot_hash_differs():
    key1 = compute_cache_key(prompt="p", model="m", params={}, kb_snapshot_hash="aaa")
    key2 = compute_cache_key(prompt="p", model="m", params={}, kb_snapshot_hash="bbb")
    assert key1 != key2


def test_cache_key_differs_when_cri_snapshot_hash_differs():
    key1 = compute_cache_key(prompt="p", model="m", params={}, cri_snapshot_hash="aaa")
    key2 = compute_cache_key(prompt="p", model="m", params={}, cri_snapshot_hash="bbb")
    assert key1 != key2


def test_cache_key_insensitive_to_params_dict_key_order():
    key1 = compute_cache_key(prompt="p", model="m", params={"a": 1, "b": 2})
    key2 = compute_cache_key(prompt="p", model="m", params={"b": 2, "a": 1})
    assert key1 == key2


def test_get_returns_none_for_missing_key(tmp_path):
    cache = ContentAddressedCache(tmp_path / "cache")
    assert cache.get("does-not-exist") is None


def test_put_then_get_roundtrips(tmp_path):
    cache = ContentAddressedCache(tmp_path / "cache")
    cache.put("key1", {"output": {"a": 1}, "usage": {"prompt_tokens": 1, "completion_tokens": 2}})
    assert cache.get("key1") == {"output": {"a": 1}, "usage": {"prompt_tokens": 1, "completion_tokens": 2}}


def test_put_is_immutable_for_existing_key(tmp_path):
    cache = ContentAddressedCache(tmp_path / "cache")
    cache.put("key1", {"value": "first"})
    cache.put("key1", {"value": "second"})
    assert cache.get("key1") == {"value": "first"}


def test_put_creates_cache_dir_if_missing(tmp_path):
    cache_dir = tmp_path / "nested" / "cache"
    cache = ContentAddressedCache(cache_dir)
    cache.put("key1", {"value": "x"})
    assert cache_dir.is_dir()
    assert cache.get("key1") == {"value": "x"}


def test_put_leaves_no_temp_files_behind(tmp_path):
    cache_dir = tmp_path / "cache"
    cache = ContentAddressedCache(cache_dir)
    cache.put("key1", {"value": "x"})
    remaining = list(cache_dir.iterdir())
    assert remaining == [cache_dir / "key1.json"]


def test_put_creates_the_cache_dir_and_entry_with_restrictive_permissions(tmp_path):
    """Security-review finding, fixed here: this cache stores the full
    text of every prompt sent to the LLM and every raw completion
    received -- it must not rely on its parent directory happening to
    already be locked down; it needs to enforce owner-only permissions
    itself, exactly like every other storage writer in the codebase."""
    cache_dir = tmp_path / "nested" / "cache"
    cache = ContentAddressedCache(cache_dir)
    cache.put("key1", {"value": "x"})

    assert stat.S_IMODE(cache_dir.stat().st_mode) == 0o700
    assert stat.S_IMODE((cache_dir / "key1.json").stat().st_mode) == 0o600
