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
EBICS_URL=https://testplattform.zkb.ch/ebicsweb/ebicsweb   # note: /ebicsweb/ebicsweb
EBICS_PARTNER_ID=<test Partner ID>
EBICS_USER_ID=<test User ID>

EBICS_KEYRING_PATH=../local/test-keyring.json
EBICS_KEYRING_PASSPHRASE=<a passphrase you choose>

# Verify HPB against the bank-key hashes ZKB publishes for the "mit Schlüsseln" profile.
EBICS_BANK_X002_HASH=<from ZKB>
EBICS_BANK_E002_HASH=<from ZKB>
```

> **Profile.** ZKB offers EBICS 3.0 **"mit Schlüsseln"** (self-signed keys — what this client
> implements) and **"mit Zertifikaten"** (CA certificates); each has *different* bank-key hashes.
> Use the "mit Schlüsseln" hashes.
>
> **Download BTF.** The test platform's subscriber configuration lists the Business Transaction
> Formats it serves. The `download` step below uses the production `EOP/camt.053` BTF
> (`ServiceName=EOP`, `Scope=CH`, `MsgName=camt.053` v`08`, `Container=ZIP`) that
> `Client.download` sends — confirm that BTF appears in the platform's own list before running.
> (An earlier draft of this doc claimed the test platform only accepts an `XTD` order type; that
> was uncited and is not relied on here — treat the platform's configuration UI as the oracle.)

## 2. Install and sanity-check locally first

```bash
uv sync --group dev          # installs reportlab (PDF letter) and certifi (TLS trust) too
uv run ruff check && uv run mypy --strict src && uv run pytest
```

All three must be green before you touch the network.

> **TLS trust.** Some Python builds (notably the python.org macOS build) ship an empty system
> trust store, so HTTPS verification fails with `CERTIFICATE_VERIFY_FAILED`. The transport falls
> back to the Mozilla CA bundle when the optional `certifi` (`tls` extra) is importable — the dev
> group above already includes it. For a non-dev install, add it with
> `pip install "ebicsclient[tls]"`.

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

Once `HPB` succeeds, download the statements — this exercises the full three-phase download
(initialisation → transfer → receipt), the segment reassembly, and the order-data decryption:

```bash
# 6) Fetch the EOP/camt.053 statements and print their closing balances.
#    Set EBICS_DOWNLOAD_PATH to also write the raw order data (a ZIP) for inspection.
uv run python examples/zkb_handshake.py download
```

The `download` step re-runs `HPB` first (a fresh process holds no bank keys), then opens the
download transaction. It prints the number of statements and, per statement, the account and
closing balance.

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

- **`download`** — a `ReturnCodeError` at initialisation with code `090005`
  (`EBICS_NO_DOWNLOAD_DATA_AVAILABLE`) simply means the test account has no statements for the
  period; it is not a bug. A rejection on the BTF (e.g. `091005` unsupported order type) means
  the `EOP/camt.053` BTF is not what the platform serves — check its configuration and adjust.
  If the transaction succeeds but `CryptoError` is raised while decrypting, the **order-data
  cipher** is the suspect (as with `hpb`). If decryption succeeds but `MessageFormatError` is
  raised, the payload parsed as bytes but is not the camt.053 shape the parser expects —
  inspect it via `EBICS_DOWNLOAD_PATH`.

## 5. When it works

Green `INI`/`HIA`/`HPB` against the test platform validates the whole handshake end to end,
including the two failure-prone areas. A successful `download` on top of that validates the
three-phase download transaction, segment reassembly, order-data decryption, and camt.053
parsing — the complete read (MVP) path.
