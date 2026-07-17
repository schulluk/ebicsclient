"""Tests for input validation at the library's public boundaries.

The bug class under test: a caller-supplied value of the wrong type (typically a numeric
value from an unquoted YAML/JSON config entry) slipping deep into a C extension and
surfacing as a cryptic error — as happened live with a numeric ``user_id`` reaching
``x509.NameAttribute`` (``TypeError: value argument must be a str``). Every boundary must
fail immediately, with a message that teaches the fix. EBICS identifiers with leading
zeros (``"00123456"``) also *lose their zeros* when parsed as numbers, so the messages
point at quoting the config value, never at wrapping it in ``str()``.
"""

from pathlib import Path

import pytest

from ebicsclient import (
    Bank,
    BankKeyHashes,
    BankKeys,
    BusinessTransactionFormat,
    Client,
    Keyring,
    MappingCertificateProvider,
    TrustAnchorVerifier,
    User,
    generate_keyring,
    load_certificate,
    load_keyring,
    save_keyring,
)
from ebicsclient.errors import CertificateError, KeyringError, TransportError
from ebicsclient.keys import CertificateUsage
from ebicsclient.models import PAIN_001
from ebicsclient.transport import Transport


@pytest.fixture(scope="module")
def keyring() -> Keyring:
    return generate_keyring()


def test_user_rejects_a_numeric_id_with_a_teaching_message() -> None:
    # The exact bug report: ZKB IDs like "00123456" unquoted in config arrive as ints.
    with pytest.raises(TypeError) as caught:
        User(partner_id="00123456", user_id=123456)  # type: ignore[arg-type]
    message = str(caught.value)
    assert "user_id must be a str" in message
    assert "int" in message
    assert "quote" in message  # the fix, not just the failure


def test_user_rejects_an_empty_id() -> None:
    with pytest.raises(ValueError):
        User(partner_id="PARTNER1", user_id="  ")


def test_bank_rejects_a_non_string_host_id() -> None:
    with pytest.raises(TypeError) as caught:
        Bank(host_id=12345, url="https://example.com/ebicsweb")  # type: ignore[arg-type]
    assert "host_id must be a str" in str(caught.value)


def test_business_transaction_format_rejects_a_numeric_message_version() -> None:
    # The classic YAML trap: an unquoted "08" arrives as the int 8 — wrong type AND a
    # silently different version.
    with pytest.raises(TypeError) as caught:
        BusinessTransactionFormat(
            service_name="EOP",
            message_name="camt.053",
            message_version=8,  # type: ignore[arg-type]
        )
    assert "message_version must be a str" in str(caught.value)


def test_keyring_rejects_non_key_values() -> None:
    with pytest.raises(TypeError) as caught:
        Keyring(signature="not-a-key", authentication="x", encryption="y")  # type: ignore[arg-type]
    assert "signature must be an RSA private key" in str(caught.value)


def test_bank_keys_reject_private_keys() -> None:
    keys = generate_keyring()
    with pytest.raises(TypeError):
        BankKeys(authentication=keys.authentication, encryption=keys.encryption)  # type: ignore[arg-type]


def test_bank_key_hashes_reject_a_hex_string() -> None:
    digest = b"\x00" * 32
    with pytest.raises(TypeError) as caught:
        BankKeyHashes(authentication="18 72 B2 39", encryption=digest)  # type: ignore[arg-type]
    assert "bytes.fromhex" in str(caught.value)  # the message teaches the conversion


def test_bank_key_hashes_reject_a_wrong_length() -> None:
    with pytest.raises(ValueError):
        BankKeyHashes(authentication=b"\x00" * 32, encryption=b"\x00" * 20)


def test_save_and_load_keyring_accept_a_str_path(tmp_path: Path, keyring: Keyring) -> None:
    # The README quickstart passes a plain string path — it must work.
    path = str(tmp_path / "keyring.json")
    save_keyring(keyring, path, "passphrase")
    loaded = load_keyring(path, "passphrase")
    assert loaded.signature.public_key().public_numbers() == (
        keyring.signature.public_key().public_numbers()
    )


def test_serialize_keyring_rejects_a_non_string_passphrase(
    tmp_path: Path, keyring: Keyring
) -> None:
    with pytest.raises(KeyringError) as caught:
        save_keyring(keyring, tmp_path / "keyring.json", 123456)  # type: ignore[arg-type]
    assert "passphrase must be a str" in str(caught.value)


def test_load_keyring_rejects_a_non_string_passphrase(tmp_path: Path, keyring: Keyring) -> None:
    path = tmp_path / "keyring.json"
    save_keyring(keyring, path, "passphrase")
    with pytest.raises(KeyringError):
        load_keyring(path, 123456)  # type: ignore[arg-type]


def test_upload_rejects_a_string_document(keyring: Keyring) -> None:
    client = Client(
        Bank(host_id="HOST", url="https://example.com/ebicsweb"),
        User(partner_id="PARTNER1", user_id="USER1"),
        keyring,
    )
    with pytest.raises(TypeError) as caught:
        client.upload(PAIN_001, "<Document/>")  # type: ignore[arg-type]
    message = str(caught.value)
    assert "order_data must be bytes" in message
    assert "'rb'" in message  # the fix is in the message


def test_transport_rejects_a_non_string_url() -> None:
    with pytest.raises(TransportError) as caught:
        Transport(12345)  # type: ignore[arg-type]
    assert "must be a str" in str(caught.value)


def test_make_ini_letter_rejects_a_non_string_branding(keyring: Keyring) -> None:
    client = Client(
        Bank(host_id="HOST", url="https://example.com/ebicsweb"),
        User(partner_id="PARTNER1", user_id="USER1"),
        keyring,
    )
    with pytest.raises(TypeError) as caught:
        client.make_ini_letter(branding=42)  # type: ignore[arg-type]
    assert "branding must be a str" in str(caught.value)


def test_load_certificate_rejects_a_pem_string() -> None:
    with pytest.raises(CertificateError) as caught:
        load_certificate("-----BEGIN CERTIFICATE-----")  # type: ignore[arg-type]
    assert "'rb'" in str(caught.value)


def test_trust_anchor_verifier_rejects_non_certificate_anchors() -> None:
    with pytest.raises(TypeError) as caught:
        TrustAnchorVerifier(["not-a-certificate"])  # type: ignore[list-item]
    assert "load_certificate()" in str(caught.value)


def test_mapping_certificate_provider_rejects_non_certificate_values() -> None:
    with pytest.raises(TypeError) as caught:
        MappingCertificateProvider({CertificateUsage.SIGNATURE: b"DER bytes"})  # type: ignore[dict-item]
    assert "load_certificate()" in str(caught.value)


def test_the_original_bug_now_fails_at_construction_not_in_cryptography() -> None:
    # Regression for the live report: with a numeric user_id the failure must happen at
    # User(...) with our message — never reach x509.NameAttribute inside cryptography.
    with pytest.raises(TypeError) as caught:
        User(partner_id=123456, user_id=123456)  # type: ignore[arg-type]
    assert "value argument must be a str" not in str(caught.value)
    assert "leading zeros" in str(caught.value)