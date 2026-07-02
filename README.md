# ebicsclient — a pure-Python EBICS 3.0 (H005) client

A from-scratch, pure-Python client for the **EBICS** banking protocol, scoped initially to
**downloading account statements (camt.053) from Swiss banks** — starting with Zürcher
Kantonalbank (ZKB).

- **Stack:** Python 3.11+, just two runtime deps — `cryptography` (RSA/AES) and `lxml` (XML /
  exclusive-c14n); everything else stdlib. No PHP/Java sidecar. (Rationale: [docs/04-implementation-plan.md](docs/04-implementation-plan.md#dependencies).)
- **License model:** source-available — **free for personal use, paid license for commercial/business use**
  (see [docs/02-licensing-strategy.md](docs/02-licensing-strategy.md)).
- **Reusable & app-agnostic:** designed to be embedded as a dependency in a downstream application,
  not tied to any one consumer — a stable, reusable standard.

## Why this exists

EBICS access now requires **EBICS 3.0 / H005** (the pre-3.0 protocol was retired ~Nov 2025), and the
ISO 20022 "2009" message vintage retires **21 Nov 2026** — so a client must speak H005 and consume
**camt.053.001.08** (the 2019 vintage). There is no pure-Python client for this. We build one, kept
tightly scoped. EBICS is a stable, formally versioned standard, so a scoped client is **low ongoing
maintenance** — the cost is upfront correctness. See
[docs/03-library-landscape.md](docs/03-library-landscape.md) for the landscape.

## Documentation index

| Doc | Contents |
|---|---|
| [docs/01-protocol-and-formats.md](docs/01-protocol-and-formats.md) | EBICS/H005 background, the two regulatory deadlines, message formats (camt.053.001.08) |
| [docs/02-licensing-strategy.md](docs/02-licensing-strategy.md) | Dual-licensing plan, legal reasoning, what a license actually buys, reimplementation |
| [docs/03-library-landscape.md](docs/03-library-landscape.md) | Existing EBICS libraries and the gap this library fills |
| [docs/04-implementation-plan.md](docs/04-implementation-plan.md) | Scope, modules, the two hard parts, build order, test strategy |
| [docs/05-zkb-onboarding.md](docs/05-zkb-onboarding.md) | The INI/HIA + signed-letter ceremony, ZKB BTF/order params |
| [docs/06-engineering-conventions.md](docs/06-engineering-conventions.md) | Baseline practices: layout, logging, errors, security, typing, testing, CI |
| [docs/07-handshake-testing.md](docs/07-handshake-testing.md) | Validating INI/HIA/HPB end to end against the ZKB test platform |
| `../local/` (outside the repo) | Real ZKB connection credentials, kept in the workspace **outside** the repo — can't be committed |

## Development

Contributors: see [CONTRIBUTING.md](CONTRIBUTING.md). One-command setup with `uv`:
`git clone https://github.com/schulluk/ebicsclient && cd ebicsclient && uv sync --all-groups`
(or `pip install -e . --group dev` on pip ≥ 25.1).
This is a money-moving library — the engineering bar is [docs/06-engineering-conventions.md](docs/06-engineering-conventions.md).

## Status

**Under active development.** Locked decisions: package name **`ebicsclient`**; runtime deps
**`cryptography` + `lxml`** only; **Python 3.11+**; MVP = **handshake + read-only download** (key
ceremony → fetch `EOP/camt.053.001.08` → parse balances), with `protocol/` and `formats/` seams left for
future EBICS versions / message formats (see [docs/04-implementation-plan.md](docs/04-implementation-plan.md)).

- [x] ~~Key generation + encrypted keyring, and EBICS public-key hashes~~
- [x] ~~Exception model with retryability classification~~
- [x] ~~Authentication signature (inclusive Canonical XML 1.0 + RSA-SHA256)~~
- [x] ~~HTTPS transport (TLS 1.2 floor, retryable error mapping)~~
- [x] ~~INI/HIA/HPB handshake (key initialisation + bank-key download)~~
- [x] ~~X.509 key transmission (EBICS 3.0 "mit Schlüsseln" self-signed certificates)~~
- [x] ~~Initialisation letter (HTML, or PDF via the optional `pdf` extra)~~
- [x] ~~Order-data decryption (RSA-unwrap + AES-128-CBC)~~
- [x] ~~Offline verification: H005 XSD validation, C14N golden vectors, ebics-client-php parity~~
- [ ] Live validation against the ZKB test platform ([docs/07](docs/07-handshake-testing.md))
- [ ] Statement download — `EOP/camt.053.001.08` BTD transaction (initialise → transfer → receipt)
- [ ] camt.053 parsing (closing balances)

## License

Source-available under the **PolyForm Noncommercial License 1.0.0** — **free for noncommercial use**;
commercial/business use requires a paid license. See [LICENSE.md](LICENSE.md) and the rationale in
[docs/02-licensing-strategy.md](docs/02-licensing-strategy.md).
