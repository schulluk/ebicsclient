"""Tests for ebicsclient.keys: keyring generation, persistence, and public-key hashes."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from ebicsclient import keys
from ebicsclient.errors import KeyringError
from ebicsclient.models import Keyring

_PASSPHRASE = "correct horse battery staple"


@pytest.fixture(scope="module")
def keyring() -> Keyring:
    """A real 2048-bit keyring, generated once for the module."""
    return keys.generate_keyring()


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


def test_keyring_round_trips_through_an_encrypted_file(keyring: Keyring, tmp_path: Path) -> None:
    path = tmp_path / "keyring.json"
    keys.save_keyring(keyring, path, passphrase=_PASSPHRASE)
    loaded = keys.load_keyring(path, passphrase=_PASSPHRASE)
    for field in ("signature", "authentication", "encryption"):
        original = getattr(keyring, field).public_key().public_numbers()
        restored = getattr(loaded, field).public_key().public_numbers()
        assert (original.e, original.n) == (restored.e, restored.n)


def test_saved_keyring_does_not_contain_plaintext_key_material(
    keyring: Keyring, tmp_path: Path
) -> None:
    path = tmp_path / "keyring.json"
    keys.save_keyring(keyring, path, passphrase=_PASSPHRASE)
    contents = path.read_text(encoding="utf-8")
    assert "ENCRYPTED PRIVATE KEY" in contents
    assert "BEGIN PRIVATE KEY" not in contents  # never unencrypted


def test_load_keyring_with_wrong_passphrase_raises(keyring: Keyring, tmp_path: Path) -> None:
    path = tmp_path / "keyring.json"
    keys.save_keyring(keyring, path, passphrase=_PASSPHRASE)
    with pytest.raises(KeyringError):
        keys.load_keyring(path, passphrase="wrong passphrase")


def test_save_keyring_rejects_an_empty_passphrase(keyring: Keyring, tmp_path: Path) -> None:
    with pytest.raises(KeyringError):
        keys.save_keyring(keyring, tmp_path / "keyring.json", passphrase="")
