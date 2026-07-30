"""Security-review finding: directories and files this platform creates
had no explicit permission hardening, inheriting the process umask
(typically world-readable). `secure_mkdir`/`secure_chmod_tree` fix this
at the one shared choke point every writer goes through.
"""

import stat

from app.services.fs_permissions import DIR_MODE, FILE_MODE, secure_chmod_tree, secure_mkdir


def _mode(path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def test_secure_mkdir_creates_an_owner_only_directory(tmp_path):
    target = tmp_path / "sub" / "leaf"
    secure_mkdir(target, parents=True)
    assert _mode(target) == DIR_MODE


def test_secure_mkdir_re_applies_mode_even_under_a_permissive_umask(tmp_path, monkeypatch):
    import os

    old_umask = os.umask(0o000)  # the most permissive umask possible
    try:
        target = tmp_path / "under-permissive-umask"
        secure_mkdir(target)
        assert _mode(target) == DIR_MODE
    finally:
        os.umask(old_umask)


def test_secure_chmod_tree_locks_down_every_file_and_subdirectory(tmp_path):
    root = tmp_path / "root"
    root.mkdir(mode=0o777)
    nested_dir = root / "nested"
    nested_dir.mkdir(mode=0o777)
    file_a = root / "a.json"
    file_a.write_text("{}")
    file_a.chmod(0o666)
    file_b = nested_dir / "b.json"
    file_b.write_text("{}")
    file_b.chmod(0o666)

    secure_chmod_tree(root)

    assert _mode(root) == DIR_MODE
    assert _mode(nested_dir) == DIR_MODE
    assert _mode(file_a) == FILE_MODE
    assert _mode(file_b) == FILE_MODE
