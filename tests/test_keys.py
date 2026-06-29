"""Tests for ebicsclient.keys: keyring generation, serialisation, and public-key hashes."""

import hashlib
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from ebicsclient import keys
from ebicsclient.errors import KeyringDecryptionError, KeyringError, KeyringFormatError
from ebicsclient.models import Keyring

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


def test_load_keyring_from_a_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(KeyringError):
        keys.load_keyring(tmp_path / "does-not-exist.json", passphrase=_PASSPHRASE)
