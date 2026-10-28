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
    download   fetch the EOP/camt.053 statements and print their closing balances
    upload     upload a pain.001 payment file (path in EBICS_UPLOAD_PATH)
    pain002    fetch the pain.002 payment status report(s) and print them
    haa        list the order types with data available at the bank
    htd        show the subscriber data registered at the bank
    hkd        show the customer data and every subscriber registered at the bank
    hpd        show the bank's EBICS parameters (versions, supported features)
    pub        replace the signature key (A006) at the bank, then the stored keyring
    hca        replace the authentication and encryption keys (X002, E002)
    hcs        replace all three keys at once

The key changes (pub/hca/hcs) need no letter. Each writes the new keyring next to the current
one first (``<keyring>.next``), sends the change, and only then moves it over the current file,
so neither keyring is lost whatever the bank answers.

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
    EBICS_BANK_X002_HASH      expected bank X002 hash, to verify HPB (spaces/case ignored);
                              the public-key hash or the certificate hash the bank publishes
    EBICS_BANK_E002_HASH      expected bank E002 hash, to verify HPB (either form likewise)
    EBICS_DOWNLOAD_PATH       where `download` writes the raw order data (default: none)
    EBICS_UPLOAD_PATH         path to the pain.001 file that `upload` sends
"""

import argparse
import logging
import os
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from dotenv import load_dotenv

from ebicsclient import (
    Bank,
    BankKeyHashes,
    BankKeyMismatchError,
    BankKeys,
    Client,
    InitializationState,
    KeyChangeUnconfirmedError,
    KeyRotation,
    OutputFormat,
    User,
    certificate_fingerprint,
    generate_keyring,
    load_keyring,
    public_key_hash,
    rotate_keyring,
    save_keyring,
)
from ebicsclient.formats import camt053
from ebicsclient.models import CAMT_053, PAIN_001, PAIN_002, Keyring

_REPO_ROOT = Path(__file__).resolve().parent.parent
_DEFAULT_ENV_FILE = _REPO_ROOT.parent / "local" / ".env"


def main() -> int:
    """Parse the chosen step and run it. Returns a process exit code."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    load_dotenv(os.environ.get("EBICS_ENV_FILE", _DEFAULT_ENV_FILE))

    parser = argparse.ArgumentParser(description="Manual EBICS handshake runner.")
    parser.add_argument(
        "step",
        choices=[
            "generate", "ini", "hia", "letter", "hpb", "hashes", "download", "upload",
            "pain002", "haa", "htd", "hkd", "hpd", "pub", "hca", "hcs",
        ],
    )
    step = parser.parse_args().step

    try:
        return _STEPS[step]()
    except KeyError as error:
        print(f"Missing environment variable: {error}", file=sys.stderr)
        return 2
    except BankKeyMismatchError as error:
        print(f"Bank-key pin mismatch — NOT trusting the keys: {error}", file=sys.stderr)
        return 1


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
    if _build_client().ini() is InitializationState.ALREADY_INITIALISED:
        print("INI: subscriber already initialised — the signature key was not re-submitted.")
    else:
        print("INI accepted: the signature key (A006) was submitted.")
    return 0


def _hia() -> int:
    if _build_client().hia() is InitializationState.ALREADY_INITIALISED:
        print("HIA: subscriber already initialised — the keys were not re-submitted.")
    else:
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
    bank_keys = _fetch_bank_keys(_build_client())
    print("HPB succeeded. Verify the bank's key hashes below against the values it publishes.")
    _report_hash(
        "Bank authentication (X002)",
        bank_keys.authentication,
        bank_keys.authentication_certificate,
        "EBICS_BANK_X002_HASH",
    )
    _report_hash(
        "Bank encryption    (E002)",
        bank_keys.encryption,
        bank_keys.encryption_certificate,
        "EBICS_BANK_E002_HASH",
    )
    return 0


def _fetch_bank_keys(client: Client) -> BankKeys:
    """Run HPB, pinning to the published bank-key hashes when both are configured."""
    return client.hpb(pinned=_pinned_hashes())


def _pinned_hashes() -> BankKeyHashes | None:
    authentication = os.environ.get("EBICS_BANK_X002_HASH")
    encryption = os.environ.get("EBICS_BANK_E002_HASH")
    if authentication is None or encryption is None:
        return None
    return BankKeyHashes(
        authentication=bytes.fromhex(_normalise(authentication)),
        encryption=bytes.fromhex(_normalise(encryption)),
    )


def _hashes() -> int:
    _print_own_hashes(_load_keyring())
    return 0


def _download() -> int:
    client = _build_client()
    # A fresh process holds no bank keys yet; fetch them (HPB) before downloading.
    _fetch_bank_keys(client)
    order_data = client.download(CAMT_053)
    print(f"Download succeeded: {len(order_data)} bytes of order data.")

    output = os.environ.get("EBICS_DOWNLOAD_PATH")
    if output is not None:
        Path(output).write_bytes(order_data)
        print(f"Wrote the raw order data to {output}")

    statements = camt053.parse(order_data)
    print(f"Parsed {len(statements)} statement(s):")
    for statement in statements:
        account = statement.iban if statement.iban is not None else "(no IBAN)"
        print(f"  {statement.identification} — {account}")
        balance = statement.closing_balance
        if balance is not None:
            print(f"    closing balance: {balance.amount} {balance.currency} "
                  f"({balance.credit_debit.value}) on {balance.date.isoformat()}")
        print(f"    entries: {len(statement.entries)}")
    return 0


def _upload() -> int:
    path = Path(os.environ["EBICS_UPLOAD_PATH"])
    order_data = path.read_bytes()
    client = _build_client()
    # A fresh process holds no bank keys yet; fetch them (HPB) before uploading.
    _fetch_bank_keys(client)
    transaction_id = client.upload(PAIN_001, order_data)
    print(f"Upload accepted: {len(order_data)} bytes, transaction {transaction_id}.")
    print("The bank accepted the EBICS envelope, signature, and encryption.")
    print("Download the pain.002 (via the 'download' step with the PSR BTF) for the result.")
    return 0


def _pain002() -> int:
    import io
    import zipfile

    client = _build_client()
    _fetch_bank_keys(client)
    order_data = client.download(PAIN_002)
    print(f"pain.002 download succeeded: {len(order_data)} bytes.")
    # pain.002 comes as a ZIP of status-report XML documents; print each.
    with zipfile.ZipFile(io.BytesIO(order_data)) as archive:
        for name in sorted(archive.namelist()):
            print(f"----- {name} -----")
            print(archive.read(name).decode("utf-8", errors="replace"))
    return 0


def _haa() -> int:
    client = _build_client()
    _fetch_bank_keys(client)
    order_types = client.available_order_types()
    if not order_types:
        print("HAA: no order types currently have data available.")
        return 0
    print(f"HAA: {len(order_types)} order type(s) with data available:")
    for btf in order_types:
        print(f"  {btf.service_name}/{btf.scope or '-'}/{btf.message_name}"
              f" v{btf.message_version or '-'} container={btf.container or '-'}")
    return 0


def _htd() -> int:
    client = _build_client()
    _fetch_bank_keys(client)
    info = client.subscriber_info()
    print(f"HTD: user {info.user_id} (status {info.user_status}), name: {info.name}")
    print(f"  permissions: {len(info.permissions)}, partner order types: {len(info.order_types)}")
    for entry in info.order_types:
        service = entry.service
        btf = (f"{service.service_name}/{service.scope or '-'}/{service.message_name}"
               f" v{service.message_version or '-'}") if service else "-"
        print(f"  {entry.admin_order_type:<4} {btf:<40} {entry.description or ''}")
    return 0


def _hkd() -> int:
    client = _build_client()
    _fetch_bank_keys(client)
    info = client.customer_info()
    print(f"HKD: host {info.host_id}, customer: {info.address.name}")
    print(f"  accounts: {len(info.accounts)}, customer order types: {len(info.order_types)}")
    for account in info.accounts:
        numbers = ", ".join(number.value for number in account.account_numbers)
        print(f"  account {account.identification} ({account.currency}): {numbers}")
    for subscriber in info.subscribers:
        print(f"  subscriber {subscriber.user_id} (status {subscriber.user_status}), "
              f"name: {subscriber.name}, permissions: {len(subscriber.permissions)}")
        for permission in subscriber.permissions:
            level = permission.authorisation_level
            print(f"    {permission.admin_order_type:<4} "
                  f"signature class {level.value if level is not None else '-'}")
    return 0


def _hpd() -> int:
    client = _build_client()
    _fetch_bank_keys(client)
    parameters = client.bank_parameters()
    print(f"HPD: {parameters.institute} (host {parameters.host_id or '-'})")
    for url in parameters.urls:
        valid_from = url.valid_from.isoformat() if url.valid_from is not None else "now"
        print(f"  URL {url.url} (valid from {valid_from})")
    print(f"  protocol versions:       {' '.join(parameters.protocol_versions)}")
    print(f"  authentication versions: {' '.join(parameters.authentication_versions)}")
    print(f"  encryption versions:     {' '.join(parameters.encryption_versions)}")
    print(f"  signature versions:      {' '.join(parameters.signature_versions)}")
    print(f"  recovery: {parameters.supports_recovery}, "
          f"pre-validation: {parameters.supports_pre_validation}, "
          f"HKD/HTD: {parameters.supports_client_data_download}, "
          f"HAA: {parameters.supports_downloadable_order_data}")
    return 0


def _change_keys(rotation: KeyRotation) -> int:
    path = _keyring_path()
    successor_path = path.with_name(f"{path.name}.next")
    if successor_path.exists():
        print(f"Refusing: {successor_path} is left over from an unfinished key change. Find out "
              f"which keyring the bank holds before removing either file.", file=sys.stderr)
        return 1
    client = _build_client()
    _fetch_bank_keys(client)
    successor = rotate_keyring(client.keyring, rotation)
    # 1. The new keys are safe on disk before the bank can switch to them.
    save_keyring(successor, successor_path, _passphrase())
    try:
        # 2. The bank switches; the client adopts the successor only on a confirmed success.
        transaction_id = client.change_keys(successor, rotation)
    except KeyChangeUnconfirmedError as error:
        print(f"UNCONFIRMED: {error}", file=sys.stderr)
        print(f"Kept both {path} (old keys) and {successor_path} (new keys).", file=sys.stderr)
        return 1
    except Exception:
        # Anything else means the bank kept the old keys: the successor is useless.
        successor_path.unlink()
        raise
    # 3. Promote the successor over the old keyring in one atomic rename.
    os.replace(successor_path, path)
    print(f"Key change accepted (transaction {transaction_id}); {path} now holds the new keys.")
    _print_own_hashes(successor)
    return 0


def _pub() -> int:
    return _change_keys(KeyRotation.SIGNATURE)


def _hca() -> int:
    return _change_keys(KeyRotation.AUTHENTICATION_AND_ENCRYPTION)


def _hcs() -> int:
    return _change_keys(KeyRotation.ALL)


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


def _report_hash(
    label: str,
    public_key: rsa.RSAPublicKey,
    certificate: x509.Certificate | None,
    env_name: str,
) -> None:
    """Print a bank key's hash in each published form and whether the expected value matches one.

    A bank publishes the public-key hash (the ``e m`` form) or, in EBICS 3.0, the SHA-256 of
    the key's certificate in DER form; ZKB publishes both for the same key. A key the bank
    delivered without a certificate has the public-key form only.
    """
    forms = [("public-key hash", public_key_hash(public_key))]
    if certificate is not None:
        forms.append(("certificate hash", certificate_fingerprint(certificate)))
    print(f"  {label}:")
    for form_name, digest in forms:
        print(f"    {form_name:<16} {_grouped(digest)}")
    expected = os.environ.get(env_name)
    if expected is None:
        print(f"    (set {env_name} to either value to verify this automatically)")
        return
    matching = [form_name for form_name, digest in forms if _normalise(expected) == digest.hex()]
    if matching:
        print(f"    MATCH ({matching[0]}) — the bank key is authentic.")
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
    "download": _download,
    "upload": _upload,
    "pain002": _pain002,
    "haa": _haa,
    "htd": _htd,
    "hkd": _hkd,
    "hpd": _hpd,
    "pub": _pub,
    "hca": _hca,
    "hcs": _hcs,
}


if __name__ == "__main__":
    raise SystemExit(main())
