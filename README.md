# ebicsclient — a pure-Python EBICS 3.0 (H005) client

A from-scratch, pure-Python client for the **EBICS** banking protocol. It **downloads account
statements (camt.053)** and **initiates payments (pain.001)** over EBICS 3.0 / H005 — starting with
Zürcher Kantonalbank (ZKB), against which the whole flow is validated live.

- **Stack:** Python 3.11+, just two runtime deps — `cryptography` (RSA/AES) and `lxml` (XML /
  inclusive Canonical XML 1.0); everything else stdlib. No PHP/Java sidecar. (Rationale:
  [docs/04-implementation-plan.md](docs/04-implementation-plan.md#dependencies).)
- **License model:** source-available — **free for personal use, paid license for commercial/business use**
  (see [docs/02-licensing-strategy.md](docs/02-licensing-strategy.md)).
- **Reusable & app-agnostic:** designed to be embedded as a dependency in a downstream application,
  not tied to any one consumer — a stable, reusable standard.

## Why this exists

EBICS access now requires **EBICS 3.0 / H005** (the pre-3.0 protocol was retired ~Nov 2025), and the
ISO 20022 "2009" message vintage retires **21 Nov 2026** — so a client must speak H005 and consume
**camt.053.001.08** (the 2019 vintage) and submit **pain.001.001.09** payments. There is no other
pure-Python client for this. We build one, kept tightly scoped. EBICS is a stable, formally versioned
standard, so a scoped client is **low ongoing maintenance** — the cost is upfront correctness. See
[docs/03-library-landscape.md](docs/03-library-landscape.md) for the landscape.

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

The **certificate-based ("mit Zertifikaten")** profile is a constructor option — see
[docs/11-certificate-profiles.md](docs/11-certificate-profiles.md).

## Documentation index

| Doc | Contents |
|---|---|
| [docs/01-protocol-and-formats.md](docs/01-protocol-and-formats.md) | EBICS/H005 background, the two regulatory deadlines, message formats |
| [docs/02-licensing-strategy.md](docs/02-licensing-strategy.md) | Dual-licensing plan, legal reasoning, reimplementation |
| [docs/03-library-landscape.md](docs/03-library-landscape.md) | Existing EBICS libraries and the gap this library fills |
| [docs/04-implementation-plan.md](docs/04-implementation-plan.md) | Scope, modules, the two hard parts, build order, test strategy |
| [docs/05-zkb-onboarding.md](docs/05-zkb-onboarding.md) | The INI/HIA + signed-letter ceremony, ZKB BTF/order params |
| [docs/06-engineering-conventions.md](docs/06-engineering-conventions.md) | Baseline practices: layout, logging, errors, security, typing, testing, CI |
| [docs/07-handshake-testing.md](docs/07-handshake-testing.md) | Validating INI/HIA/HPB + download/upload against the ZKB test platform |
| [docs/08-parity-and-xsd-findings.md](docs/08-parity-and-xsd-findings.md) | The inclusive-vs-exclusive c14n correction and verification discipline |
| [docs/09-zkb-test-platform-settings.md](docs/09-zkb-test-platform-settings.md) | What the ZKB test platform exposes, and its upload/simulation model |
| [docs/10-btf-order-types.md](docs/10-btf-order-types.md) | ZKB's EBICS order-type → H005 BTF catalogue |
| [docs/11-certificate-profiles.md](docs/11-certificate-profiles.md) | "mit Schlüsseln" vs "mit Zertifikaten", and the certificate seam |
| `../local/` (outside the repo) | Real ZKB connection credentials, kept in the workspace **outside** the repo — can't be committed |

## Development

Contributors: see [CONTRIBUTING.md](CONTRIBUTING.md). One-command setup with `uv`:
`git clone https://github.com/schulluk/ebicsclient && cd ebicsclient && uv sync --all-groups`
(or `pip install -e . --group dev` on pip ≥ 25.1).
This is a money-moving library — the engineering bar is [docs/06-engineering-conventions.md](docs/06-engineering-conventions.md).

## Status

**Read and write validated live against the ZKB test platform.** The key ceremony, the statement
download path, and the payment upload (envelope, authentication signature, A006 electronic signature,
and order-data encryption) are all accepted by the bank, and the camt.053 parser is validated against
a real bank statement.

**Milestone 1 — Key ceremony** (validated live on ZKB)

- [x] Key generation + encrypted keyring, and EBICS public-key hashes
- [x] Authentication signature (inclusive Canonical XML 1.0 + RSA-SHA256)
- [x] HTTPS transport (TLS 1.2 floor, certifi fallback via the optional `tls` extra)
- [x] INI/HIA/HPB handshake
- [x] X.509 key transmission: **mit Schlüsseln** (self-signed) and **mit Zertifikaten** (CA certs)
- [x] Initialisation letter (HTML, or PDF via the optional `pdf` extra)
- [x] Bank-key pinning across sessions (`hpb(pinned=...)`)

**Milestone 2 — Read** (validated live on ZKB)

- [x] Order-data decryption (RSA-unwrap + AES-128-CBC)
- [x] Statement download — `EOP/camt.053` BTD transaction (initialise → transfer → receipt)
- [x] camt.053 parsing (balances + entries) — validated on a real ZKB statement

**Milestone 3 — Write** (validated live on ZKB)

- [x] Order-data encryption and the A006 electronic signature (RSASSA-PSS)
- [x] Payment upload — `MCT/pain.001` BTU transaction — accepted live

**Milestone 4 — Verification & release**

- [x] Exception model with retryability classification
- [x] Offline verification: H005 XSD validation, C14N golden vectors, ebics-client-php parity
- [x] Golden regression fixture from a real ZKB statement
- [x] CI (ruff / mypy --strict / pytest) and tag-triggered PyPI releases (Trusted Publishing)

**Milestone 5 — Message formats** (parsers built against genuine ZKB messages)

- [x] pain.002 status-report parser (group / payment / transaction statuses, reason codes)
- [x] camt.052 intraday reports
- [x] camt.054 booking advices (incl. the QRR / SCOR / LSV variants via `service_option`)

**Milestone 6 — Protocol conveniences & breadth**

- [ ] Subscriber self-inspection — available order types (HAA) and subscriber info (HTD)
- [ ] Distributed signatures (EDS)
- [ ] Further EBICS versions (e.g. H004) via the `protocol/` seam

## License

Source-available under the **PolyForm Noncommercial License 1.0.0** — **free for noncommercial use**;
commercial/business use requires a paid license. See [LICENSE.md](LICENSE.md) and the rationale in
[docs/02-licensing-strategy.md](docs/02-licensing-strategy.md).
