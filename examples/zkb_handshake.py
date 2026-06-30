"""Manual end-to-end EBICS handshake against a live bank (e.g. the ZKB test platform).

This is **not** a unit test: it talks to a real bank and is meant to be run by hand, one
step at a time, while bringing a subscriber online. It is configured entirely through
environment variables and never contains credentials itself.

Steps, matching the EBICS initialisation ceremony (see docs/05, docs/07):

    generate   create the three RSA key pairs and save them as an encrypted keyring
    ini        submit the signature public key (A006)
    hia        submit the authentication and encryption public keys (X002, E002)
    letter     render the initialisation letter to sign and send to the bank
    hpb        download the bank's public keys and verify their hashes
    hashes     print your own public-key hashes (what the letter certifies)

Run each step in order, e.g.::

    uv run python examples/zkb_handshake.py generate
    uv run python examples/zkb_handshake.py ini
    uv run python examples/zkb_handshake.py hia
    uv run python examples/zkb_handshake.py letter
    # ... print, sign, and mail the letter; wait for the bank to activate you ...
    uv run python examples/zkb_handshake.py hpb

Required environment variables (load them from a file *outside* the repository):

    EBICS_HOST_ID            bank Host ID (test platform value)
    EBICS_URL                bank EBICS HTTPS endpoint (test platform value)
    EBICS_PARTNER_ID         your Partner/customer ID
    EBICS_USER_ID            your User/subscriber ID
    EBICS_KEYRING_PATH       where to store the encrypted keyring
    EBICS_KEYRING_PASSPHRASE passphrase that encrypts the keyring

Optional:

    EBICS_ENV_FILE           dotenv file to load (default: ../local/.env)
    EBICS_LETTER_PATH         output path for the letter (default: ./ini-letter)
    EBICS_BANK_X002_HASH      expected bank X002 hash, to verify HPB (spaces/case ignored)
    EBICS_BANK_E002_HASH      expected bank E002 hash, to verify HPB
"""

import argparse
import logging
import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import rsa
from dotenv import load_dotenv

from ebicsclient import (
    Bank,
    Client,
    OutputFormat,
    User,
    generate_keyring,
    load_keyring,
    public_key_hash,
    save_keyring,
)
from ebicsclient.models import Keyring

_REPO_ROOT = Path(__file__).resolve().parent.parent
_DEFAULT_ENV_FILE = _REPO_ROOT.parent / "local" / ".env"


def main() -> int:
    """Parse the chosen step and run it. Returns a process exit code."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    load_dotenv(os.environ.get("EBICS_ENV_FILE", _DEFAULT_ENV_FILE))

    parser = argparse.ArgumentParser(description="Manual EBICS handshake runner.")
    parser.add_argument(
        "step", choices=["generate", "ini", "hia", "letter", "hpb", "hashes"]
    )
    step = parser.parse_args().step

    try:
        return _STEPS[step]()
    except KeyError as error:
        print(f"Missing environment variable: {error}", file=sys.stderr)
        return 2


def _generate() -> int:
    path = _keyring_path()
    if path.exists():
        print(f"Refusing to overwrite an existing keyring at {path}", file=sys.stderr)
        return 1
    keyring = generate_keyring()
    save_keyring(keyring, path, _passphrase())
    print(f"Wrote a new encrypted keyring to {path}")
    _print_own_hashes(keyring)
    return 0


def _ini() -> int:
    _build_client().ini()
    print("INI accepted: the signature key (A006) was submitted.")
    return 0


def _hia() -> int:
    _build_client().hia()
    print("HIA accepted: the authentication (X002) and encryption (E002) keys were submitted.")
    return 0


def _letter() -> int:
    letter = _build_client().make_ini_letter(output_format=OutputFormat.AUTO)
    suffix = ".pdf" if letter.output_format is OutputFormat.PDF else ".html"
    path = Path(os.environ.get("EBICS_LETTER_PATH", "ini-letter")).with_suffix(suffix)
    path.write_bytes(letter.content)
    print(f"Wrote the {letter.output_format.value.upper()} initialisation letter to {path}")
    print("Print it, sign it by hand, and send it to the bank to activate your keys.")
    return 0


def _hpb() -> int:
    bank_keys = _build_client().hpb()
    print("HPB succeeded. Verify the bank's public-key hashes below.")
    _report_hash("Bank authentication (X002)", bank_keys.authentication, "EBICS_BANK_X002_HASH")
    _report_hash("Bank encryption    (E002)", bank_keys.encryption, "EBICS_BANK_E002_HASH")
    return 0


def _hashes() -> int:
    _print_own_hashes(_load_keyring())
    return 0


def _build_client() -> Client:
    return Client(_bank(), _user(), _load_keyring())


def _bank() -> Bank:
    return Bank(host_id=os.environ["EBICS_HOST_ID"], url=os.environ["EBICS_URL"])


def _user() -> User:
    return User(partner_id=os.environ["EBICS_PARTNER_ID"], user_id=os.environ["EBICS_USER_ID"])


def _keyring_path() -> Path:
    return Path(os.environ["EBICS_KEYRING_PATH"])


def _passphrase() -> str:
    return os.environ["EBICS_KEYRING_PASSPHRASE"]


def _load_keyring() -> Keyring:
    return load_keyring(_keyring_path(), _passphrase())


def _print_own_hashes(keyring: Keyring) -> None:
    print("Your public-key hashes (these appear on the initialisation letter):")
    for label, private_key in (
        ("A006 signature     ", keyring.signature),
        ("X002 authentication", keyring.authentication),
        ("E002 encryption    ", keyring.encryption),
    ):
        print(f"  {label}: {_grouped(public_key_hash(private_key.public_key()))}")


def _report_hash(label: str, public_key: rsa.RSAPublicKey, env_name: str) -> None:
    actual = public_key_hash(public_key)
    print(f"  {label}: {_grouped(actual)}")
    expected = os.environ.get(env_name)
    if expected is None:
        print(f"    (set {env_name} to verify this automatically)")
        return
    if _normalise(expected) == actual.hex():
        print("    MATCH — the bank key is authentic.")
    else:
        print("    MISMATCH — do NOT trust this key; investigate before continuing.")


def _grouped(digest: bytes) -> str:
    return " ".join(f"{byte:02X}" for byte in digest)


def _normalise(hash_text: str) -> str:
    return hash_text.replace(" ", "").lower()


_STEPS = {
    "generate": _generate,
    "ini": _ini,
    "hia": _hia,
    "letter": _letter,
    "hpb": _hpb,
    "hashes": _hashes,
}


if __name__ == "__main__":
    raise SystemExit(main())
