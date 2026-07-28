# ebicsclient — a pure-Python EBICS 3.0 (H005) client

A Python client for the **EBICS** banking protocol (EBICS 3.0 / H005):
download statements and initiate payments over a single, source-available library. Validated
live against Zürcher Kantonalbank (ZKB).

## Install

```console
pip install ebicsclient          # add [pdf] for PDF letters, [tls] for the certifi CA bundle
```

## Quickstart

```python
from ebicsclient import Bank, User, Client, generate_keyring, save_keyring, PAIN_001

bank = Bank(host_id="ZKBKCHZZ", url="https://ebicsweb.example.com/ebicsweb")
user = User(partner_id="PARTNER1", user_id="USER1")

# 1. Generate the three RSA key pairs (once) and store them encrypted.
keyring = generate_keyring()
save_keyring(keyring, "keyring.json", passphrase="…")

client = Client(bank, user, keyring)

# 2. Key initialisation: submit your keys, then print/sign/send the letter and wait for activation.
client.ini()
client.hia()
letter = client.make_ini_letter()          # HTML, or PDF with the optional [pdf] extra
# … send letter.content to the bank; once activated:

# 3. Fetch the bank's public keys (verify their published hashes out of band).
client.hpb()

# 4. Read: download and parse the end-of-day statements.
for statement in client.download_statements():
    print(statement.iban, statement.closing_balance)

# 5. Write: initiate a payment (a pain.001.001.09 document, as bytes).
transaction_id = client.upload(PAIN_001, pain001_bytes)
```

The certificate-based (*mit Zertifikaten*) profile is a constructor option — see
[docs/11-certificate-profiles.md](https://github.com/schulluk/ebicsclient/blob/main/docs/11-certificate-profiles.md).

More worked examples — a non-acking peek, a consume-safe sync, a dated backfill, a payment
round-trip, and certificate-profile onboarding — are in
[examples/](https://github.com/schulluk/ebicsclient/blob/main/examples/README.md).

> ### ⚠️ Loading EBICS identifiers from a config file? Quote them.
>
> EBICS IDs **can** carry leading zeros (a real Partner ID may look like `00123456`) and ISO
> versions look like `"08"`. Unquoted in YAML/JSON/TOML these parse as **numbers** — the wrong
> type *and* silently stripped of their zeros. Always quote them (`partner_id: "00123456"`); the
> library rejects non-string values, but the fix is quoting, never `str()`-wrapping the parsed
> number (which keeps the wrong, zero-stripped identifier). The same applies to numeric-looking
> keyring passphrases.

## What it does

Key ceremony (INI/HIA/HPB), statement/report downloads (camt.053/052/054, pain.002) with optional
dated ranges, and payment uploads (pain.001) — read and write validated live against ZKB. Pure
Python (`cryptography`, `lxml`), no PHP/Java sidecar. Not yet built: multi-person signatures
(EDS/VEU), key rotation, and several administrative order types.

Full capability-by-capability coverage, gaps, and verification status:
**[docs/13-standard-conformance.md](https://github.com/schulluk/ebicsclient/blob/main/docs/13-standard-conformance.md)**.

## Why this exists

It was built for [WealthTracker](https://github.com/schulluk/WealthTracker), which needs to pull
bank statements over EBICS — and no pure-Python client for EBICS 3.0 (H005) existed to build on.
Rather than shell out to a PHP/Java sidecar or a proprietary dependency, ebicsclient is a clean,
reusable library that any application can embed. See
[docs/03-library-landscape.md](https://github.com/schulluk/ebicsclient/blob/main/docs/03-library-landscape.md) for the existing options and the gap.

## Why only EBICS 3.0 (H005)?

By design. EBICS access now requires **H005** (the pre-3.0 protocol was retired ~Nov 2025), and
the ISO 20022 "2009" message vintage retires **21 Nov 2026** — so supporting legacy versions
would be building for the past. The `protocol/` layer is seamed for a *future* EBICS version, not
older ones. The regulatory deadlines are in [docs/01](https://github.com/schulluk/ebicsclient/blob/main/docs/01-protocol-and-formats.md); the scope
decision in [docs/04](https://github.com/schulluk/ebicsclient/blob/main/docs/04-implementation-plan.md).

## Documentation

| Doc | Contents |
|---|---|
| [docs/01-protocol-and-formats.md](https://github.com/schulluk/ebicsclient/blob/main/docs/01-protocol-and-formats.md) | EBICS/H005 background, the two regulatory deadlines, message formats |
| [docs/02-licensing-strategy.md](https://github.com/schulluk/ebicsclient/blob/main/docs/02-licensing-strategy.md) | Dual-licensing plan, legal reasoning, reimplementation |
| [docs/03-library-landscape.md](https://github.com/schulluk/ebicsclient/blob/main/docs/03-library-landscape.md) | Existing EBICS libraries and the gap this library fills |
| [docs/04-implementation-plan.md](https://github.com/schulluk/ebicsclient/blob/main/docs/04-implementation-plan.md) | Scope, modules, the two hard parts, build order, test strategy |
| [docs/05-zkb-onboarding.md](https://github.com/schulluk/ebicsclient/blob/main/docs/05-zkb-onboarding.md) | The INI/HIA + signed-letter ceremony, re-initialisation, ZKB order params |
| [docs/06-engineering-conventions.md](https://github.com/schulluk/ebicsclient/blob/main/docs/06-engineering-conventions.md) | Baseline practices: layout, logging, errors, security, typing, testing, CI |
| [docs/07-handshake-testing.md](https://github.com/schulluk/ebicsclient/blob/main/docs/07-handshake-testing.md) | Validating INI/HIA/HPB + download/upload against the ZKB test platform |
| [docs/08-parity-and-xsd-findings.md](https://github.com/schulluk/ebicsclient/blob/main/docs/08-parity-and-xsd-findings.md) | The inclusive-vs-exclusive c14n correction and verification discipline |
| [docs/09-zkb-test-platform-settings.md](https://github.com/schulluk/ebicsclient/blob/main/docs/09-zkb-test-platform-settings.md) | What the ZKB test platform exposes, and its upload/simulation model |
| [docs/10-btf-order-types.md](https://github.com/schulluk/ebicsclient/blob/main/docs/10-btf-order-types.md) | ZKB's EBICS order-type → H005 BTF catalogue |
| [docs/11-certificate-profiles.md](https://github.com/schulluk/ebicsclient/blob/main/docs/11-certificate-profiles.md) | "mit Schlüsseln" vs "mit Zertifikaten", and the certificate seam |
| [docs/12-verification-ledger.md](https://github.com/schulluk/ebicsclient/blob/main/docs/12-verification-ledger.md) | Every protocol claim → spec citation → oracle → status; the 2.5→3.0 audit |
| [docs/13-standard-conformance.md](https://github.com/schulluk/ebicsclient/blob/main/docs/13-standard-conformance.md) | Coverage & gaps: every H005 order type — supported or not, and how far verified |

## Development

Contributors: see [CONTRIBUTING.md](https://github.com/schulluk/ebicsclient/blob/main/CONTRIBUTING.md). One-command setup with `uv`:
`git clone https://github.com/schulluk/ebicsclient && cd ebicsclient && uv sync --all-groups`
(or `pip install -e . --group dev` on pip ≥ 25.1). This is a money-moving library — the
engineering bar is [docs/06-engineering-conventions.md](https://github.com/schulluk/ebicsclient/blob/main/docs/06-engineering-conventions.md).

## License

Source-available under the **PolyForm Noncommercial License 1.0.0** — **free for noncommercial
use**; commercial/business use requires a paid license. See
[LICENSE.md](https://github.com/schulluk/ebicsclient/blob/main/LICENSE.md) and the
rationale in [docs/02-licensing-strategy.md](https://github.com/schulluk/ebicsclient/blob/main/docs/02-licensing-strategy.md).
