"""Tests for ebicsclient.keys: keyring generation, serialisation, and public-key hashes."""

import dataclasses
import hashlib
import os
import stat
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa

from ebicsclient import keys
from ebicsclient.errors import KeyringDecryptionError, KeyringError, KeyringFormatError
from ebicsclient.models import BankKeys, Keyring, KeyRotation

_PASSPHRASE = "correct horse battery staple"


@pytest.fixture(scope="module")
def keyring() -> Keyring:
    """A real 2048-bit keyring, generated once for the module."""
    return keys.generate_keyring()


def _assert_same_public_keys(left: Keyring, right: Keyring) -> None:
    for field in ("signature", "authentication", "encryption"):
        a = getattr(left, field).public_key().public_numbers()
        b = getattr(right, field).public_key().public_numbers()
        assert (a.e, a.n) == (b.e, b.n)


def test_generate_keyring_produces_three_distinct_2048_bit_keys(keyring: Keyring) -> None:
    for private_key in (keyring.signature, keyring.authentication, keyring.encryption):
        assert private_key.key_size == 2048
        assert private_key.public_key().public_numbers().e == 65537
    moduli = {
        keyring.signature.public_key().public_numbers().n,
        keyring.authentication.public_key().public_numbers().n,
        keyring.encryption.public_key().public_numbers().n,
    }
    assert len(moduli) == 3  # the three key pairs are independent


def test_generate_keyring_rejects_keys_below_the_ebics_minimum() -> None:
    with pytest.raises(KeyringError):
        keys.generate_keyring(key_size=1024)


def test_fingerprint_data_is_lowercase_hex_zero_stripped_space_joined() -> None:
    # Exponent 65537 -> "10001"; modulus 0xABCDEF -> "abcdef"; single space between.
    numbers = rsa.RSAPublicNumbers(e=65537, n=0xABCDEF)
    assert keys._fingerprint_data(numbers) == b"10001 abcdef"


def test_public_key_hash_is_sha256_of_the_fingerprint(keyring: Keyring) -> None:
    public_key = keyring.signature.public_key()
    numbers = public_key.public_numbers()
    expected = hashlib.sha256(f"{numbers.e:x} {numbers.n:x}".encode("ascii")).digest()
    digest = keys.public_key_hash(public_key)
    assert digest == expected
    assert len(digest) == 32


def test_keyring_round_trips_in_memory(keyring: Keyring) -> None:
    data = keys.serialize_keyring(keyring, passphrase=_PASSPHRASE)
    assert isinstance(data, bytes)
    _assert_same_public_keys(keys.deserialize_keyring(data, passphrase=_PASSPHRASE), keyring)


def test_serialized_keyring_contains_only_encrypted_key_material(keyring: Keyring) -> None:
    data = keys.serialize_keyring(keyring, passphrase=_PASSPHRASE)
    assert b"ENCRYPTED PRIVATE KEY" in data
    assert b"BEGIN PRIVATE KEY" not in data  # never an unencrypted key


def test_serialize_keyring_rejects_an_empty_passphrase(keyring: Keyring) -> None:
    with pytest.raises(KeyringError):
        keys.serialize_keyring(keyring, passphrase="")


def test_deserialize_keyring_with_wrong_passphrase_raises_decryption_error(
    keyring: Keyring,
) -> None:
    data = keys.serialize_keyring(keyring, passphrase=_PASSPHRASE)
    with pytest.raises(KeyringDecryptionError):
        keys.deserialize_keyring(data, passphrase="wrong passphrase")


def test_deserialize_keyring_rejects_malformed_data_with_format_error() -> None:
    with pytest.raises(KeyringFormatError):
        keys.deserialize_keyring(b"not json at all", passphrase=_PASSPHRASE)


def test_deserialize_keyring_rejects_unknown_format_version() -> None:
    with pytest.raises(KeyringFormatError):
        keys.deserialize_keyring(b'{"version": 999, "keys": {}}', passphrase=_PASSPHRASE)


def test_keyring_error_subclasses_stay_catchable_as_the_base(keyring: Keyring) -> None:
    # Callers that only care about "some keyring problem" can still catch the base.
    data = keys.serialize_keyring(keyring, passphrase=_PASSPHRASE)
    with pytest.raises(KeyringError):
        keys.deserialize_keyring(data, passphrase="wrong passphrase")


def test_save_and_load_keyring_round_trip_through_a_file(keyring: Keyring, tmp_path: Path) -> None:
    path = tmp_path / "keyring.json"
    keys.save_keyring(keyring, path, passphrase=_PASSPHRASE)
    _assert_same_public_keys(keys.load_keyring(path, passphrase=_PASSPHRASE), keyring)


def test_save_keyring_replaces_an_existing_file_and_leaves_no_temporary_behind(
    keyring: Keyring, tmp_path: Path
) -> None:
    path = tmp_path / "keyring.json"
    keys.save_keyring(keys.generate_keyring(), path, passphrase=_PASSPHRASE)
    keys.save_keyring(keyring, path, passphrase=_PASSPHRASE)
    _assert_same_public_keys(keys.load_keyring(path, passphrase=_PASSPHRASE), keyring)
    assert [entry.name for entry in tmp_path.iterdir()] == ["keyring.json"]


@pytest.mark.skipif(os.name != "posix", reason="POSIX file modes")
def test_save_keyring_writes_an_owner_only_file(keyring: Keyring, tmp_path: Path) -> None:
    path = tmp_path / "keyring.json"
    keys.save_keyring(keyring, path, passphrase=_PASSPHRASE)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_a_failed_save_keeps_the_previous_keyring_intact(
    keyring: Keyring, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The atomic write must never leave a half-written keyring where the old one was —
    # after a key change, losing either keyring can lock the subscriber out.
    path = tmp_path / "keyring.json"
    keys.save_keyring(keyring, path, passphrase=_PASSPHRASE)
    before = path.read_bytes()

    def _fail(source: str | os.PathLike[str], destination: str | os.PathLike[str]) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(os, "replace", _fail)
    with pytest.raises(KeyringError):
        keys.save_keyring(keys.generate_keyring(), path, passphrase=_PASSPHRASE)
    assert path.read_bytes() == before
    assert [entry.name for entry in tmp_path.iterdir()] == ["keyring.json"]


@pytest.mark.parametrize(
    ("rotation", "replaced"),
    [
        (KeyRotation.SIGNATURE, {"signature"}),
        (KeyRotation.AUTHENTICATION_AND_ENCRYPTION, {"authentication", "encryption"}),
        (KeyRotation.ALL, {"signature", "authentication", "encryption"}),
    ],
)
def test_rotate_keyring_replaces_exactly_the_rotated_keys(
    keyring: Keyring, rotation: KeyRotation, replaced: set[str]
) -> None:
    successor = keys.rotate_keyring(keyring, rotation)
    for field in ("signature", "authentication", "encryption"):
        old = getattr(keyring, field).public_key().public_numbers()
        new = getattr(successor, field).public_key().public_numbers()
        assert (old != new) is (field in replaced), field
        assert getattr(successor, field).key_size == 2048
    keys.validate_key_change(keyring, successor, rotation)  # a well-formed change


def test_rotate_keyring_rejects_keys_below_the_ebics_minimum(keyring: Keyring) -> None:
    with pytest.raises(KeyringError):
        keys.rotate_keyring(keyring, KeyRotation.ALL, key_size=1024)


def test_rotate_keyring_rejects_a_plain_string_rotation(keyring: Keyring) -> None:
    with pytest.raises(TypeError, match="KeyRotation"):
        keys.rotate_keyring(keyring, "all")  # type: ignore[arg-type]


def test_validate_key_change_rejects_a_changed_key_the_order_does_not_cover(
    keyring: Keyring,
) -> None:
    # HCA must leave A006 alone, or client and bank would disagree on the signature key.
    successor = keys.rotate_keyring(keyring, KeyRotation.ALL)
    with pytest.raises(ValueError, match="signature key unchanged"):
        keys.validate_key_change(keyring, successor, KeyRotation.AUTHENTICATION_AND_ENCRYPTION)


def test_validate_key_change_rejects_an_unchanged_rotated_key(keyring: Keyring) -> None:
    with pytest.raises(ValueError, match="one of the current keys"):
        keys.validate_key_change(keyring, keyring, KeyRotation.SIGNATURE)


def test_validate_key_change_rejects_a_current_key_moved_into_another_role(
    keyring: Keyring,
) -> None:
    moved = dataclasses.replace(keyring, signature=keyring.authentication)
    with pytest.raises(ValueError, match="one of the current keys"):
        keys.validate_key_change(keyring, moved, KeyRotation.SIGNATURE)


def test_validate_key_change_rejects_one_new_key_used_for_two_roles(keyring: Keyring) -> None:
    # EBICS_KEYMGMT_DUPLICATE_KEY (Annex 1): refused before anything is sent.
    shared = keys.generate_keyring().authentication
    successor = dataclasses.replace(keyring, authentication=shared, encryption=shared)
    with pytest.raises(ValueError, match="two roles"):
        keys.validate_key_change(keyring, successor, KeyRotation.AUTHENTICATION_AND_ENCRYPTION)


def test_validate_key_change_rejects_a_short_new_key(keyring: Keyring) -> None:
    short = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    with pytest.raises(KeyringError):
        keys.validate_key_change(
            keyring, dataclasses.replace(keyring, signature=short), KeyRotation.SIGNATURE
        )


def test_validate_key_change_rejects_a_non_keyring_successor(keyring: Keyring) -> None:
    with pytest.raises(TypeError, match="Keyring"):
        keys.validate_key_change(keyring, "keyring.json", KeyRotation.ALL)  # type: ignore[arg-type]


def test_load_keyring_from_a_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(KeyringError):
        keys.load_keyring(tmp_path / "does-not-exist.json", passphrase=_PASSPHRASE)


def test_bank_key_hashes_are_derived_independently_per_key() -> None:
    # Guard the pinning property: the X002 and E002 hashes are computed from two SEPARATE
    # keys, not both from one. With two distinct bank keys the hashes must differ and each
    # must equal public_key_hash of its own key. (A bank may genuinely reuse one key for
    # both — e.g. ZKB's plain-keys profile — in which case identical hashes are expected,
    # not a bug; see docs/05.)
    bank = keys.generate_keyring()  # three independent keys
    bank_keys = BankKeys(
        authentication=bank.authentication.public_key(),
        encryption=bank.encryption.public_key(),
    )
    hashes = keys.bank_key_hashes(bank_keys)
    assert hashes.authentication == keys.public_key_hash(bank_keys.authentication)
    assert hashes.encryption == keys.public_key_hash(bank_keys.encryption)
    assert hashes.authentication != hashes.encryption  # distinct keys → distinct hashes


def test_self_signed_certificate_wraps_the_public_key(keyring: Keyring) -> None:
    certificate = keys.generate_self_signed_certificate(
        keyring.signature, "USER1", keys.CertificateUsage.SIGNATURE
    )
    embedded = certificate.public_key()
    assert isinstance(embedded, rsa.RSAPublicKey)
    assert embedded.public_numbers() == keyring.signature.public_key().public_numbers()
    assert certificate.issuer == certificate.subject  # self-signed
    # A006 signature certs must carry nonRepudiation (content_commitment) key usage.
    key_usage = certificate.extensions.get_extension_for_class(x509.KeyUsage).value
    assert key_usage.content_commitment
    assert not key_usage.digital_signature


def test_self_signed_certificates_are_deterministic(keyring: Keyring) -> None:
    # The EBICS 3.0 initialisation letters print the SHA-256 of the certificate's DER, and
    # the bank compares it against the certificate INI/HIA transmitted — possibly sessions
    # earlier. Regeneration must therefore be byte-identical from the keyring alone.
    from cryptography.hazmat.primitives.serialization import Encoding

    first = keys.generate_self_signed_certificate(
        keyring.signature, "USER1", keys.CertificateUsage.SIGNATURE
    )
    second = keys.generate_self_signed_certificate(
        keyring.signature, "USER1", keys.CertificateUsage.SIGNATURE
    )
    assert first.public_bytes(Encoding.DER) == second.public_bytes(Encoding.DER)
    assert keys.certificate_fingerprint(first) == keys.certificate_fingerprint(second)


def test_self_signed_certificates_differ_per_key_and_usage(keyring: Keyring) -> None:
    signature = keys.generate_self_signed_certificate(
        keyring.signature, "USER1", keys.CertificateUsage.SIGNATURE
    )
    authentication = keys.generate_self_signed_certificate(
        keyring.authentication, "USER1", keys.CertificateUsage.AUTHENTICATION
    )
    assert signature.serial_number != authentication.serial_number
    assert keys.certificate_fingerprint(signature) != keys.certificate_fingerprint(
        authentication
    )


def test_self_signed_certificate_validity_is_fixed_and_unlimited(keyring: Keyring) -> None:
    # Fixed dates are what make regeneration deterministic; the Swiss Market Practice
    # Guidelines (section 6.1) explicitly allow unlimited validity (9999-12-31).
    certificate = keys.generate_self_signed_certificate(
        keyring.encryption, "USER1", keys.CertificateUsage.ENCRYPTION
    )
    assert certificate.not_valid_before_utc.year == 2020
    assert certificate.not_valid_after_utc.year == 9999
    assert 0 < certificate.serial_number < 2**160  # RFC 5280: positive, at most 20 octets


def test_certificate_fingerprint_is_sha256_over_der(keyring: Keyring) -> None:
    import hashlib

    from cryptography.hazmat.primitives.serialization import Encoding

    certificate = keys.generate_self_signed_certificate(
        keyring.signature, "USER1", keys.CertificateUsage.SIGNATURE
    )
    expected = hashlib.sha256(certificate.public_bytes(Encoding.DER)).digest()
    assert keys.certificate_fingerprint(certificate) == expected
