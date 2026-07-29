from app.services.intel.storage import (
    article_exists,
    compute_content_hash,
    read_article,
    write_article,
)


def test_write_then_read_round_trips_verbatim_text(tmp_path):
    article_dir = write_article(
        tmp_path, "This is the verbatim article text.", source_url="https://example.com/a", fetched_at="2026-01-01T00:00:00Z"
    )
    record = read_article(article_dir)
    assert record.raw_text == "This is the verbatim article text."
    assert record.source_url == "https://example.com/a"
    assert record.content_hash == compute_content_hash("This is the verbatim article text.")


def test_writing_identical_content_twice_is_a_no_op(tmp_path):
    write_article(tmp_path, "same text", source_url="https://a.example", fetched_at="2026-01-01T00:00:00Z")
    dir2 = write_article(tmp_path, "same text", source_url="https://b.example", fetched_at="2026-02-02T00:00:00Z")
    record = read_article(dir2)
    # first write wins; identical content is never re-written
    assert record.source_url == "https://a.example"


def test_different_content_produces_different_hashes(tmp_path):
    dir1 = write_article(tmp_path, "article one", source_url=None, fetched_at="2026-01-01T00:00:00Z")
    dir2 = write_article(tmp_path, "article two", source_url=None, fetched_at="2026-01-01T00:00:00Z")
    assert dir1 != dir2


def test_pasted_text_has_no_source_url(tmp_path):
    article_dir = write_article(tmp_path, "pasted content", source_url=None, fetched_at="2026-01-01T00:00:00Z")
    record = read_article(article_dir)
    assert record.source_url is None


def test_article_exists_reflects_storage_state(tmp_path):
    content_hash = compute_content_hash("some text")
    assert article_exists(tmp_path, content_hash) is False
    write_article(tmp_path, "some text", source_url=None, fetched_at="2026-01-01T00:00:00Z")
    assert article_exists(tmp_path, content_hash) is True
