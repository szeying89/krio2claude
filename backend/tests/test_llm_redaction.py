from app.services.llm.redaction import redact_secrets


def test_anthropic_key_redacted():
    text = "here is my key: sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789"
    result = redact_secrets(text)
    assert "sk-ant-api03" not in result.redacted_text
    assert result.findings[0].kind == "anthropic_api_key"


def test_aws_access_key_redacted():
    text = "AWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP"
    result = redact_secrets(text)
    assert "AKIAABCDEFGHIJKLMNOP" not in result.redacted_text


def test_private_key_block_redacted():
    text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\n-----END RSA PRIVATE KEY-----"
    result = redact_secrets(text)
    assert "MIIEpAIBAAKCAQEA" not in result.redacted_text


def test_jwt_redacted():
    text = "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dQw4w9WgXcQ"
    result = redact_secrets(text)
    assert "eyJhbGciOiJIUzI1NiJ9" not in result.redacted_text


def test_generic_password_assignment_redacted():
    text = 'config = { "password": "hunter2_super_secret" }'
    result = redact_secrets(text)
    assert "hunter2_super_secret" not in result.redacted_text


def test_clean_text_produces_no_findings():
    text = "This document describes the payment gateway architecture."
    result = redact_secrets(text)
    assert result.findings == ()
    assert result.redacted_text == text


def test_reveal_reconstructs_original_for_local_display_only():
    text = "key: sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789"
    result = redact_secrets(text)
    assert result.reveal() == text
    assert result.redacted_text != text


def test_multiple_secrets_all_redacted_with_distinct_placeholders():
    text = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789 and AKIAABCDEFGHIJKLMNOP"
    result = redact_secrets(text)
    assert len(result.findings) == 2
    assert len({f.placeholder for f in result.findings}) == 2
