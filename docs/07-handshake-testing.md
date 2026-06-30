# Testing the handshake against ZKB

The handshake — `INI` → `HIA` → initialisation letter → `HPB` — is implemented and covered
by offline tests (key round-trips, signature sign/verify, order-data decryption, envelope
structure). Offline tests prove *internal consistency*; they cannot prove agreement with a
real bank. This document is the **live validation** step: run the handshake against the ZKB
**test platform** (`testplattform.zkb.ch`) and confirm each message is accepted.

> Two parts can only be validated here, not offline (see [CLAUDE.md](../CLAUDE.md) and
> [docs/01](01-protocol-and-formats.md)): the **AuthSignature** over the
> `authenticate="true"` nodes (first exercised by `HPB`) and the **order-data cipher** used
> to decrypt the `HPB` response. If a step fails, those are the prime suspects.

## 1. Get test-platform access and credentials

The values in `../local/` are **production** *Bankparameterdaten*. The test platform issues
its **own** Host ID, Partner/User ID, endpoint URL, and bank-key hashes — request test
access from ZKB Kompetenzcenter Services (`support.epayment@zkb.ch`).

Put the test values in a dotenv file **outside the repository** (e.g. `../local/.env`, which
is gitignored). Never commit them.

```dotenv
EBICS_HOST_ID=<test Host ID>
EBICS_URL=https://testplattform.zkb.ch/ebicsweb   # confirm the exact path with ZKB
EBICS_PARTNER_ID=<test Partner ID>
EBICS_USER_ID=<test User ID>

EBICS_KEYRING_PATH=../local/test-keyring.json
EBICS_KEYRING_PASSPHRASE=<a passphrase you choose>

# Optional: fill in once you know the test platform's bank-key hashes, to auto-verify HPB.
EBICS_BANK_X002_HASH=
EBICS_BANK_E002_HASH=
```

## 2. Install and sanity-check locally first

```bash
uv sync --group dev          # installs reportlab too, so the PDF letter path works
uv run ruff check && uv run mypy --strict src && uv run pytest
```

All three must be green before you touch the network.

## 3. Run the handshake, one step at a time

A runnable, credential-free runner lives at
[examples/zkb_handshake.py](../examples/zkb_handshake.py); it reads the environment above.

```bash
# 1) Generate the three RSA key pairs and store them as an encrypted keyring.
uv run python examples/zkb_handshake.py generate

# 2) Submit your signature key (A006).
uv run python examples/zkb_handshake.py ini

# 3) Submit your authentication (X002) and encryption (E002) keys.
uv run python examples/zkb_handshake.py hia

# 4) Render the initialisation letter (PDF if reportlab is installed, else HTML).
uv run python examples/zkb_handshake.py letter
#    -> print it, sign it by hand, mail it to ZKB, and WAIT for activation.

# 5) After ZKB activates you: download and verify the bank's public keys.
uv run python examples/zkb_handshake.py hpb
```

Steps 1–4 do not depend on ZKB having activated you, so you can confirm `INI`/`HIA` are
accepted immediately. Step 5 only works once the signed letter has been processed.

## 4. What to expect, and how to read failures

- **`ini` / `hia`** — success prints an accepted message; the bank returned `000000`. A
  non-OK code raises `ReturnCodeError` carrying the EBICS code and report text. Common
  early codes: `091002` (user unknown/wrong state — expected if you re-run `ini` after it
  already succeeded) and `061099`/`091304` (internal/format — suspect envelope structure
  against the H005 XSD; the structural choices are named constants at the top of
  [h005.py](../src/ebicsclient/protocol/h005.py)).

- **`letter`** — writes `ini-letter.pdf` (or `.html`). It lists, per key, the exponent,
  modulus, and the SHA-256 hash that ZKB checks against the keys it received.

- **`hpb`** — this is the first **signed** request, so a signature-related rejection here
  (e.g. `091304` "authentication failed" / `061099`) points at the **AuthSignature**:
  exclusive-c14n byte-exactness, which nodes are digested, the SignedInfo construction.
  If the request is accepted but decryption raises `CryptoError`, the **order-data cipher**
  is the suspect: the null IV, PKCS#7 padding, or the RSA unwrap of the transaction key.

- **Hash verification** — `hpb` prints the bank's X002/E002 hashes. Compare them against the
  values ZKB publishes for the test platform (set `EBICS_BANK_*_HASH` to have the runner do
  it for you). A **mismatch means do not trust the keys** — stop and investigate.

## 5. When it works

Green `INI`/`HIA`/`HPB` against the test platform validates the whole handshake end to end,
including the two failure-prone areas. That is the gate for moving on to the statement
download (`EOP/camt.053.001.08`), which is the next milestone after the handshake.
