"""Rotate all three subscriber keys at the bank — without a new initialisation letter.

An activated subscriber can replace its keys in one EBICS order: ``HCS`` swaps the signature
(A006), authentication (X002), and encryption (E002) keys at once. The order is signed with
the *current* keys and the bank switches the moment it has processed it — so the one thing
that must never happen is losing the new keys after the bank has adopted them. The sequence
below makes that impossible:

1. generate the successor keyring and write it **next to** the current one;
2. send the change — the client adopts the new keys only once the bank confirms;
3. move the successor over the current keyring in one atomic rename.

If step 2 fails, the bank kept the old keys and the successor file is deleted. If its outcome
is unknown (``KeyChangeUnconfirmedError`` — e.g. the connection dropped after the order was
sent), both files are kept so you can find out which set the bank holds.

    uv run python examples/06_key_rotation.py
"""

import os
from pathlib import Path

from ebicsclient import KeyChangeUnconfirmedError, KeyRotation, rotate_keyring, save_keyring

from _config import load_environment, online_client


def main() -> int:
    """Replace all three keys at the bank and promote the stored keyring afterwards."""
    load_environment()
    client = online_client()
    keyring_path = Path(os.environ["EBICS_KEYRING_PATH"])
    successor_path = keyring_path.with_name(f"{keyring_path.name}.next")
    if successor_path.exists():
        print(f"{successor_path} is left over from an earlier, unconfirmed key change — find out "
              f"which keyring the bank holds before rotating again.")
        return 1

    # 1. Fresh keys for all three roles, safely on disk before the bank can switch to them.
    successor = rotate_keyring(client.keyring, KeyRotation.ALL)
    save_keyring(successor, successor_path, os.environ["EBICS_KEYRING_PASSPHRASE"])

    try:
        # 2. HCS, signed and authenticated with the current keys.
        transaction_id = client.change_keys(successor, KeyRotation.ALL)
    except KeyChangeUnconfirmedError as error:
        print(f"Outcome unknown, both keyrings kept: {error}")
        return 1
    except Exception:
        successor_path.unlink()  # the bank kept the old keys; the successor is useless
        raise

    # 3. The bank now holds the new keys: make them the stored keyring, atomically.
    os.replace(successor_path, keyring_path)
    print(f"Keys rotated (transaction {transaction_id}); {keyring_path} holds the new keys.")
    # The client already uses them — e.g. client.subscriber_info() works straight away.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
