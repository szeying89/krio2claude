import io
import zipfile

import pytest

from app.services.zip_bomb_guard import ZipBombError, reject_if_zip_bomb


def _archive_with_entry(payload: bytes) -> io.BytesIO:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("payload.xml", payload)
    buffer.seek(0)
    return buffer


def test_normal_small_archive_passes():
    archive = _archive_with_entry(b"a small, ordinary payload")
    reject_if_zip_bomb(archive)  # must not raise


def test_rejects_archive_exceeding_the_absolute_uncompressed_size_cap():
    # Incompressible-ish random-like content so the ratio check alone
    # wouldn't fire -- only the absolute size cap should.
    import os

    payload = os.urandom(1000)
    archive = _archive_with_entry(payload)
    with pytest.raises(ZipBombError, match="byte limit"):
        reject_if_zip_bomb(archive, max_uncompressed_bytes=500)


def test_rejects_archive_with_an_anomalous_compression_ratio():
    archive = _archive_with_entry(b"0" * 50_000_000)
    with pytest.raises(ZipBombError, match="compression ratio"):
        reject_if_zip_bomb(archive)


def test_stream_position_is_restored_after_the_check():
    archive = _archive_with_entry(b"ordinary payload")
    archive.seek(0)
    reject_if_zip_bomb(archive)
    assert archive.tell() == 0


def test_works_given_a_path_not_only_a_stream(tmp_path):
    path = tmp_path / "archive.zip"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("payload.xml", b"ordinary payload")
    reject_if_zip_bomb(path)  # must not raise


def test_non_zip_input_raises_the_underlying_bad_zip_file_error():
    with pytest.raises(zipfile.BadZipFile):
        reject_if_zip_bomb(io.BytesIO(b"not a zip at all"))
