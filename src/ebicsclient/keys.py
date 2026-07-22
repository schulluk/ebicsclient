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

import datetime
import hashlib
import json
import logging
from enum import StrEnum
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from ebicsclient.errors import KeyringDecryptionError, KeyringError, KeyringFormatError
from ebicsclient.models import BankKeyHashes, BankKeys, Keyring

logger = logging.getLogger(__name__)

# EBICS H005 requires RSA keys of at least 2048 bits; 65537 is the standard exponent.
_MINIMUM_KEY_SIZE = 2048
_PUBLIC_EXPONENT = 65537
_KEYRING_FORMAT_VERSION = 1
_KEY_FIELDS = ("signature", "authentication", "encryption")

# Self-signed certificates for the key-based ("mit Schlüsseln") profile are DETERMINISTIC:
# regenerating one for the same key always yields byte-identical DER. That matters because
# EBICS 3.0 initialisation letters carry the SHA-256 hash of the DER-encoded certificate
# (EBICS 3.0 spec, section 4.4.1.2.3), and the bank compares it against the certificate it
# received over INI/HIA — so the letter must be able to reproduce that exact certificate
# from the keyring alone, in any later session. Determinism comes from fixed validity
# dates, a serial derived from the key, and RSA PKCS#1 v1.5 signing (which is itself
# deterministic). The Swiss Market Practice Guidelines EBICS 3.0 (section 6.1) explicitly
# allow any validity value including unlimited (9999-12-31).
_CERTIFICATE_NOT_BEFORE = datetime.datetime(2020, 1, 1, tzinfo=datetime.UTC)
_CERTIFICATE_NOT_AFTER = datetime.datetime(9999, 12, 31, 23, 59, 59, tzinfo=datetime.UTC)
# RFC 5280 caps serial numbers at 20 octets; 16 digest bytes stay comfortably below.
_CERTIFICATE_SERIAL_BYTES = 16


def _require_passphrase(passphrase: object) -> None:
    # A non-str passphrase (e.g. a numeric value from an unquoted config entry) would
    # surface as an AttributeError deep in the serialisation layer; fail here instead.
    if not isinstance(passphrase, str):
        raise KeyringError(
            f"passphrase must be a str, got {type(passphrase).__name__} — quote it in "
            f"your configuration"
        )
    if not passphrase:
        raise KeyringError("A non-empty passphrase is required to encrypt the keyring")


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


class CertificateUsage(StrEnum):
    """The EBICS role a certificate certifies, which fixes its X.509 Key Usage.

    EBICS validates each certificate's Key Usage extension against its role and rejects a
    mismatch (return code ``091210`` EBICS_X509_WRONG_KEY_USAGE).
    """

    SIGNATURE = "signature"  # A006 — nonRepudiation
    AUTHENTICATION = "authentication"  # X002 — digitalSignature
    ENCRYPTION = "encryption"  # E002 — keyEncipherment


def _key_usage(usage: CertificateUsage) -> x509.KeyUsage:
    return x509.KeyUsage(
        digital_signature=usage is CertificateUsage.AUTHENTICATION,
        content_commitment=usage is CertificateUsage.SIGNATURE,  # a.k.a. nonRepudiation
        key_encipherment=usage is CertificateUsage.ENCRYPTION,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=False,
        crl_sign=False,
        encipher_only=False,
        decipher_only=False,
    )


def generate_self_signed_certificate(
    private_key: rsa.RSAPrivateKey, common_name: str, usage: CertificateUsage
) -> x509.Certificate:
    """Generate a deterministic self-signed X.509 certificate carrying an EBICS public key.

    EBICS 3.0 (H005) transmits public keys as X.509 certificates (``ds:X509Data``). In the
    key-based ("mit Schlüsseln") profile the certificate is self-signed by the very key it
    carries, and the bank extracts the public key from it. The bank *does* validate the
    certificate's Key Usage against its EBICS role, so it is set from ``usage``.

    The certificate is **deterministic**: the same key, name, and usage always produce
    byte-identical DER (fixed validity, key-derived serial, deterministic PKCS#1 v1.5
    signature). The EBICS 3.0 initialisation letters carry the SHA-256 hash of this DER
    (see :func:`certificate_fingerprint`), and the bank compares it against the certificate
    delivered over INI/HIA — determinism lets the letter reproduce that certificate from
    the keyring alone, without persisting certificates.

    Args:
        private_key: The key pair to certify; its public half is embedded and it self-signs.
        common_name: The subject/issuer common name (e.g. the subscriber's User ID).
        usage: The EBICS role, which fixes the certificate's Key Usage extension.

    Returns:
        The self-signed certificate.
    """
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(_deterministic_serial(private_key.public_key(), common_name, usage))
        .not_valid_before(_CERTIFICATE_NOT_BEFORE)
        .not_valid_after(_CERTIFICATE_NOT_AFTER)
        .add_extension(_key_usage(usage), critical=True)
        .sign(private_key, hashes.SHA256())
    )


def _deterministic_serial(
    public_key: rsa.RSAPublicKey, common_name: str, usage: CertificateUsage
) -> int:
    # A serial derived from the certified key (plus name and role) keeps regeneration
    # byte-identical while staying unique per certificate. RFC 5280 requires a positive
    # serial of at most 20 octets; 16 digest bytes always satisfy both (`or 1` covers the
    # astronomically unlikely all-zero digest).
    digest = hashlib.sha256(
        b"|".join(
            (
                _fingerprint_data(public_key.public_numbers()),
                common_name.encode("utf-8"),
                usage.value.encode("ascii"),
            )
        )
    ).digest()
    return int.from_bytes(digest[:_CERTIFICATE_SERIAL_BYTES], "big") or 1


def certificate_fingerprint(certificate: x509.Certificate) -> bytes:
    """Compute the SHA-256 fingerprint of a certificate's DER encoding.

    This is the hash the EBICS 3.0 initialisation letters print (spec section 4.4.1.2.3):
    the SHA-256 of the certificate in DER binary format, shown as uppercase hexadecimal.
    The bank compares it against the certificate received over INI/HIA before activating
    the subscriber.

    Args:
        certificate: The certificate to fingerprint.

    Returns:
        The 32-byte SHA-256 digest of the DER-encoded certificate.
    """
    return certificate.fingerprint(hashes.SHA256())


def bank_key_hashes(bank_keys: BankKeys) -> BankKeyHashes:
    """Compute the pinning hashes for a bank's public keys.

    A convenience for trust-on-first-use pinning: after a first HPB, hash the returned keys,
    persist the two hashes, and pass them back to :meth:`ebicsclient.Client.hpb` on later runs
    to detect any change in the bank's keys.

    Args:
        bank_keys: The bank's public keys (from HPB).

    Returns:
        The SHA-256 hashes of the authentication (X002) and encryption (E002) keys.
    """
    return BankKeyHashes(
        authentication=public_key_hash(bank_keys.authentication),
        encryption=public_key_hash(bank_keys.encryption),
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
    _require_passphrase(passphrase)
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
    _require_passphrase(passphrase)
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


def save_keyring(keyring: Keyring, path: str | Path, passphrase: str) -> None:
    """Write an encrypted keyring to a file (convenience over :func:`serialize_keyring`).

    Args:
        keyring: The key pairs to persist.
        path: Destination file path (a ``str`` or ``Path``); overwritten if it exists.
        passphrase: Secret used to encrypt the private keys. Never stored or logged.

    Raises:
        KeyringError: the passphrase is empty or not a string, or the file could not be
            written.
    """
    data = serialize_keyring(keyring, passphrase)
    destination = Path(path)
    try:
        destination.write_bytes(data)
    except OSError as error:
        raise KeyringError(f"Could not write keyring to {destination}: {error}") from error
    logger.info("Wrote encrypted keyring to %s", destination)


def load_keyring(path: str | Path, passphrase: str) -> Keyring:
    """Read and decrypt a keyring file (convenience over :func:`deserialize_keyring`).

    Args:
        path: Path to the encrypted keyring file (a ``str`` or ``Path``).
        passphrase: Secret used when the keyring was saved.

    Returns:
        The decrypted keyring.

    Raises:
        KeyringError: the file is missing, malformed, of an unknown version, or the
            passphrase is wrong or not a string.
    """
    source = Path(path)
    try:
        data = source.read_bytes()
    except OSError as error:
        raise KeyringError(f"Could not read keyring from {source}: {error}") from error
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
