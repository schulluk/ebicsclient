"""Shared setup for the example scripts — everything that is *not* the point of each example.

The examples in this folder each tell one small story (a non-consuming read, a dated
backfill, a payment round-trip). To keep every file focused on its own idea, the repetitive
parts — reading connection details from the environment, loading the encrypted keyring,
building the client, and fetching the bank's keys — live here.

Like ``zkb_handshake.py``, configuration comes entirely from ``EBICS_*`` environment
variables (load them from a dotenv file **outside** the repository); no example ever contains
credentials. The required variables are:

    EBICS_HOST_ID            bank Host ID
    EBICS_URL                bank EBICS HTTPS endpoint
    EBICS_PARTNER_ID         your Partner/customer ID
    EBICS_USER_ID            your User/subscriber ID
    EBICS_KEYRING_PATH       path to the encrypted keyring (see zkb_handshake.py `generate`)
    EBICS_KEYRING_PASSPHRASE passphrase that decrypts the keyring

Optional:

    EBICS_ENV_FILE           dotenv file to load (default: ../local/.env)
    EBICS_BANK_X002_HASH      expected bank X002 hash, to pin HPB (spaces/case ignored)
    EBICS_BANK_E002_HASH      expected bank E002 hash, to pin HPB
"""

import os
from pathlib import Path

from dotenv import load_dotenv

from ebicsclient import (
    Bank,
    BankCertificateVerifier,
    BankKeyHashes,
    CertificateProvider,
    Client,
    User,
    load_keyring,
)

_REPO_ROOT = Path(__file__).resolve().parent.parent
_DEFAULT_ENV_FILE = _REPO_ROOT.parent / "local" / ".env"


def load_environment() -> None:
    """Load the dotenv file named by ``EBICS_ENV_FILE`` (default ``../local/.env``).

    Missing files are ignored by ``load_dotenv`` — the variables may already be exported in
    the shell — so the examples fail later, with a clear message, only if something they
    actually need is absent.
    """
    load_dotenv(os.environ.get("EBICS_ENV_FILE", _DEFAULT_ENV_FILE))


def client_from_env(
    *,
    certificate_provider: CertificateProvider | None = None,
    bank_certificate_verifier: BankCertificateVerifier | None = None,
) -> Client:
    """Build a :class:`~ebicsclient.Client` from the ``EBICS_*`` environment variables.

    Args:
        certificate_provider: Supplies the subscriber's certificates for INI/HIA. ``None``
            keeps the library default (self-signed — the "mit Schlüsseln" profile); pass one
            for the "mit Zertifikaten" profile (see ``05_certificate_profile_onboarding.py``).
        bank_certificate_verifier: If given, validates the bank's certificates during HPB.

    Returns:
        A client configured for the bank and subscriber in the environment, with the
        subscriber's keyring loaded. It has *not* fetched the bank's keys yet — call
        :func:`online_client` (or ``client.hpb(...)``) before downloading or uploading.

    Raises:
        KeyError: a required ``EBICS_*`` variable is missing.
        KeyringError: the keyring could not be loaded or decrypted.
    """
    bank = Bank(host_id=_required("EBICS_HOST_ID"), url=_required("EBICS_URL"))
    user = User(partner_id=_required("EBICS_PARTNER_ID"), user_id=_required("EBICS_USER_ID"))
    keyring = load_keyring(
        Path(_required("EBICS_KEYRING_PATH")), _required("EBICS_KEYRING_PASSPHRASE")
    )
    if certificate_provider is None:
        # Fall through to the library's own default provider rather than overriding it.
        return Client(bank, user, keyring, bank_certificate_verifier=bank_certificate_verifier)
    return Client(
        bank,
        user,
        keyring,
        certificate_provider=certificate_provider,
        bank_certificate_verifier=bank_certificate_verifier,
    )


def online_client() -> Client:
    """Build a client and run HPB so it is ready to download or upload.

    A fresh process holds none of the bank's keys, so every download/upload needs an HPB
    first. This runs it, pinning the downloaded keys to ``EBICS_BANK_X002_HASH`` /
    ``EBICS_BANK_E002_HASH`` when both are set (the safe default — an unpinned HPB trusts
    whatever the wire delivers).

    Returns:
        A client whose :attr:`~ebicsclient.Client.bank_keys` are populated.

    Raises:
        KeyError: a required ``EBICS_*`` variable is missing.
        BankKeyMismatchError: the downloaded keys did not match the pinned hashes.
    """
    client = client_from_env()
    client.hpb(pinned=_pinned_hashes())
    return client


def _pinned_hashes() -> BankKeyHashes | None:
    authentication = os.environ.get("EBICS_BANK_X002_HASH")
    encryption = os.environ.get("EBICS_BANK_E002_HASH")
    if authentication is None or encryption is None:
        return None
    return BankKeyHashes(
        authentication=bytes.fromhex(_normalise(authentication)),
        encryption=bytes.fromhex(_normalise(encryption)),
    )


def _required(name: str) -> str:
    """Return the environment variable ``name`` or raise a ``KeyError`` naming it."""
    return os.environ[name]


def _normalise(hash_text: str) -> str:
    return hash_text.replace(" ", "").lower()
