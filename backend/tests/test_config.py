import pytest

from app.core.config import assert_bind_allowed


def test_loopback_bind_allowed_by_default():
    assert_bind_allowed("127.0.0.1", allow_non_loopback=False)
    assert_bind_allowed("localhost", allow_non_loopback=False)
    assert_bind_allowed("::1", allow_non_loopback=False)


def test_non_loopback_bind_rejected_without_flag():
    with pytest.raises(RuntimeError, match="non-loopback"):
        assert_bind_allowed("0.0.0.0", allow_non_loopback=False)


def test_non_loopback_bind_allowed_with_explicit_flag():
    assert_bind_allowed("0.0.0.0", allow_non_loopback=True)
