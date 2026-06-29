# ebicsclient — a pure-Python EBICS 3.0 (H005) client

A from-scratch, pure-Python client for the **EBICS** banking protocol, scoped initially to
**downloading account statements (camt.053) from Swiss banks** — starting with Zürcher
Kantonalbank (ZKB).

- **Stack:** Python 3.11+, just two runtime deps — `cryptography` (RSA/AES) and `lxml` (XML /
  exclusive-c14n); everything else stdlib. No PHP/Java sidecar. (Rationale: [docs/04-implementation-plan.md](docs/04-implementation-plan.md#dependencies).)
- **License model:** source-available — **free for personal use, paid license for commercial/business use**
  (see [docs/02-licensing-strategy.md](docs/02-licensing-strategy.md)).
- **First consumer:** the downstream app (`downstream app`) ZKB broker integration. This library is being
  split out as its own product because it's a stable, reusable, sellable standard — reusable.

## Why this exists

ZKB (and the CH/DE EBICS world) forces **EBICS 3.0 / H005** (pre-3.0 retired ~Nov 2025), and the
**ISO 20022 "2009" message vintage retires 21 Nov 2026** → we must speak H005 and produce/consume
**camt.053.001.08** (the 2019 vintage). The only fully-free existing Python option (`fintech`) blocks
statements from the last 3 days unless you pay. The free, full options are PHP/Java. Rather than run a
foreign-runtime sidecar in a Python stack — or pay — we implement a tightly-scoped client ourselves.
EBICS is a stable, formally-versioned standard, so a scoped client is **low ongoing maintenance**; the
cost is upfront correctness. See [docs/03-library-landscape.md](docs/03-library-landscape.md).

## Documentation index

| Doc | Contents |
|---|---|
| [docs/01-protocol-and-formats.md](docs/01-protocol-and-formats.md) | EBICS/H005 background, the two regulatory deadlines, message formats (camt.053.001.08) |
| [docs/02-licensing-strategy.md](docs/02-licensing-strategy.md) | Dual-licensing plan, legal reasoning, what a license actually buys, reimplementation |
| [docs/03-library-landscape.md](docs/03-library-landscape.md) | Existing libraries, the fintech free-tier trap, why DIY |
| [docs/04-implementation-plan.md](docs/04-implementation-plan.md) | Scope, modules, the two hard parts, build order, test strategy |
| [docs/05-zkb-onboarding.md](docs/05-zkb-onboarding.md) | The INI/HIA + signed-letter ceremony, ZKB BTF/order params |
| [docs/06-engineering-conventions.md](docs/06-engineering-conventions.md) | Baseline practices: layout, logging, errors, security, typing, testing, CI |
| `../local/` (outside the repo) | Real ZKB connection credentials, kept in the workspace **outside** the repo — can't be committed |

## Development

Contributors: see [CONTRIBUTING.md](CONTRIBUTING.md). One-command setup with `uv`:
`git clone https://github.com/schulluk/ebicsclient && cd ebicsclient && uv sync --all-groups`
(or `pip install -e . --group dev` on pip ≥ 25.1).
This is a money-moving library — the engineering bar is [docs/06-engineering-conventions.md](docs/06-engineering-conventions.md).

## Status

**Repository scaffolded; implementation not started.** In place: planning docs, engineering conventions,
the dual-license (PolyForm Noncommercial), and packaging (`pyproject.toml` + `src/ebicsclient` skeleton).
Locked decisions: package name **`ebicsclient`**; runtime deps **`cryptography` + `lxml`** only;
**Python 3.11+**; MVP = **handshake + read-only download** (key ceremony → fetch `EOP/camt.053.001.08` →
parse balances), with `protocol/` and `formats/` seams left for future EBICS versions / message formats
(see [docs/04-implementation-plan.md](docs/04-implementation-plan.md)). Next: implement per the build order,
starting with `keys.py`. ZKB subscriber is provisioned (noted (date)) but **not yet
initialized** — the INI/HIA key ceremony + signed paper letters to ZKB are the long pole and should be
kicked off early (see doc 05).

## License

Source-available under the **PolyForm Noncommercial License 1.0.0** — **free for noncommercial use**;
commercial/business use requires a paid license. See [LICENSE.md](LICENSE.md) and the rationale in
[docs/02-licensing-strategy.md](docs/02-licensing-strategy.md).
