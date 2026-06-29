"""RSA key-pair generation, keyring serialisation, and EBICS public-key hashes.

A subscriber's three RSA key pairs (A006 signature, X002 authentication, E002
encryption) are generated here, serialised to an encrypted byte string, and reduced
to the SHA-256 public-key hashes that appear on the initialisation letter and are
checked when the bank's keys are retrieved (HPB).

Serialisation is kept separate from storage: :func:`serialize_keyring` /
:func:`deserialize_keyring` move between a keyring and encrypted bytes, and the caller
decides where those bytes live — a file, a database column, a secrets manager, memory.
:func:`save_keyring` / :func:`load_keyring` are thin file conveniences over them, for
the common case; they are optional, and the library never forces key material onto disk.

Security: the keyring is encrypted at rest with a caller-supplied passphrase that is
never stored or logged. See docs/06-engineering-conventions.md.
"""

import hashlib
import json
import logging
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from ebicsclient.errors import KeyringDecryptionError, KeyringError, KeyringFormatError
from ebicsclient.models import Keyring

logger = logging.getLogger(__name__)

# EBICS H005 requires RSA keys of at least 2048 bits; 65537 is the standard exponent.
_MINIMUM_KEY_SIZE = 2048
_PUBLIC_EXPONENT = 65537
_KEYRING_FORMAT_VERSION = 1
_KEY_FIELDS = ("signature", "authentication", "encryption")


def generate_keyring(key_size: int = _MINIMUM_KEY_SIZE) -> Keyring:
    """Generate a fresh set of the three EBICS RSA key pairs.

    Args:
        key_size: RSA modulus size in bits; must be at least 2048 (EBICS H005).

    Returns:
        A keyring holding new signature (A006), authentication (X002), and
        encryption (E002) private keys.

    Raises:
        KeyringError: key_size is below the EBICS minimum of 2048 bits.
    """
    if key_size < _MINIMUM_KEY_SIZE:
        raise KeyringError(
            f"RSA key size {key_size} is below the EBICS minimum of {_MINIMUM_KEY_SIZE} bits"
        )
    logger.info("Generating three %d-bit RSA key pairs", key_size)
    return Keyring(
        signature=_generate_private_key(key_size),
        authentication=_generate_private_key(key_size),
        encryption=_generate_private_key(key_size),
    )


def public_key_hash(public_key: rsa.RSAPublicKey) -> bytes:
    """Compute the EBICS SHA-256 hash of an RSA public key.

    EBICS represents the public key as the lowercase, leading-zero-stripped
    hexadecimal of the exponent and modulus joined by a single space — for example
    ``"10001 b8f1..."`` — and takes the SHA-256 digest of those ASCII bytes. The
    result identifies the key on the initialisation letter and is compared against
    the bank's published hashes during HPB.

    Args:
        public_key: The RSA public key to hash.

    Returns:
        The 32-byte SHA-256 digest.
    """
    return hashlib.sha256(_fingerprint_data(public_key.public_numbers())).digest()


def serialize_keyring(keyring: Keyring, passphrase: str) -> bytes:
    """Serialise and encrypt a keyring into a portable byte string.

    Each private key is encoded as a PKCS#8 PEM encrypted with the passphrase, and the
    three are wrapped in a small JSON envelope. The caller decides where the returned
    bytes are stored — a file, a database column, a secrets manager — so the library
    never imposes a storage mechanism.

    Args:
        keyring: The key pairs to serialise.
        passphrase: Secret used to encrypt the private keys. Never stored or logged.

    Returns:
        The encrypted keyring as a UTF-8 encoded JSON byte string.

    Raises:
        KeyringError: the passphrase is empty.
    """
    if not passphrase:
        raise KeyringError("A non-empty passphrase is required to encrypt the keyring")
    encryption = serialization.BestAvailableEncryption(passphrase.encode("utf-8"))
    encoded = {
        field: _private_key_to_pem(getattr(keyring, field), encryption) for field in _KEY_FIELDS
    }
    envelope = {"version": _KEYRING_FORMAT_VERSION, "keys": encoded}
    return json.dumps(envelope, indent=2).encode("utf-8")


def deserialize_keyring(data: bytes, passphrase: str) -> Keyring:
    """Decrypt and reconstruct a keyring serialised by :func:`serialize_keyring`.

    Args:
        data: The encrypted keyring bytes.
        passphrase: Secret used when the keyring was serialised.

    Returns:
        The decrypted keyring.

    Raises:
        KeyringError: the data is malformed, of an unknown version, or the passphrase
            is wrong.
    """
    try:
        envelope = json.loads(data)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise KeyringFormatError(f"Keyring data is not valid JSON: {error}") from error

    if not isinstance(envelope, dict):
        raise KeyringFormatError("Keyring data is not a JSON object")
    if envelope.get("version") != _KEYRING_FORMAT_VERSION:
        raise KeyringFormatError(f"Unsupported keyring format version: {envelope.get('version')!r}")
    encoded = envelope.get("keys")
    if not isinstance(encoded, dict) or any(field not in encoded for field in _KEY_FIELDS):
        raise KeyringFormatError("Keyring data is missing one or more keys")

    secret = passphrase.encode("utf-8")
    keys = {field: _private_key_from_pem(encoded[field], secret) for field in _KEY_FIELDS}
    return Keyring(**keys)


def save_keyring(keyring: Keyring, path: Path, passphrase: str) -> None:
    """Write an encrypted keyring to a file (convenience over :func:`serialize_keyring`).

    Args:
        keyring: The key pairs to persist.
        path: Destination file path; overwritten if it already exists.
        passphrase: Secret used to encrypt the private keys. Never stored or logged.

    Raises:
        KeyringError: the passphrase is empty, or the file could not be written.
    """
    data = serialize_keyring(keyring, passphrase)
    try:
        path.write_bytes(data)
    except OSError as error:
        raise KeyringError(f"Could not write keyring to {path}: {error}") from error
    logger.info("Wrote encrypted keyring to %s", path)


def load_keyring(path: Path, passphrase: str) -> Keyring:
    """Read and decrypt a keyring file (convenience over :func:`deserialize_keyring`).

    Args:
        path: Path to the encrypted keyring file.
        passphrase: Secret used when the keyring was saved.

    Returns:
        The decrypted keyring.

    Raises:
        KeyringError: the file is missing, malformed, of an unknown version, or the
            passphrase is wrong.
    """
    try:
        data = path.read_bytes()
    except OSError as error:
        raise KeyringError(f"Could not read keyring from {path}: {error}") from error
    return deserialize_keyring(data, passphrase)


def _generate_private_key(key_size: int) -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=_PUBLIC_EXPONENT, key_size=key_size)


def _fingerprint_data(numbers: rsa.RSAPublicNumbers) -> bytes:
    return f"{numbers.e:x} {numbers.n:x}".encode("ascii")


def _private_key_to_pem(
    private_key: rsa.RSAPrivateKey,
    encryption: serialization.KeySerializationEncryption,
) -> str:
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )
    return pem.decode("ascii")


def _private_key_from_pem(pem: str, passphrase: bytes) -> rsa.RSAPrivateKey:
    try:
        key = serialization.load_pem_private_key(pem.encode("ascii"), password=passphrase)
    except ValueError as error:
        # A wrong passphrase and corrupt key material both surface here as ValueError.
        raise KeyringDecryptionError(
            "Could not decrypt the keyring — wrong passphrase or corrupt key material"
        ) from error
    if not isinstance(key, rsa.RSAPrivateKey):
        raise KeyringFormatError("Keyring contains a key that is not an RSA private key")
    return key
