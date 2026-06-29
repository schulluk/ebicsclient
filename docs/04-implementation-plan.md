# Implementation plan

## Scope (MVP)

MVP = **handshake + read-only**, nothing else. *Handshake:* the key ceremony (INI/HIA → signed letter →
HPB). *Read-only:* download statements and parse them — the 3-phase `receipt` only acknowledges delivery,
it never writes to the account. Concretely: **one bank (ZKB), H005, plain keys, profile T**, one BTF
(`EOP/camt.053.001.08`). Out of scope until MVP works end-to-end: uploads (pain.001), distributed
signatures (EDS), certificate-based keys, multi-bank quirk handling.

## Dependencies

Goal: **minimum external surface.** Exactly **two** runtime dependencies; everything else is stdlib.
That's the floor — you can't go lower without hand-rolling RSA/AES or XML canonicalization, neither of
which we will ever do. Both deps are permissive (Apache/BSD) and front a proven C library (OpenSSL,
libxml2) for precisely the two operations we must not get wrong. No GPL/AGPL. No `fintech`.

### Runtime (shipped to consumers)

- **`cryptography`** (Apache-2.0 / BSD) — *unavoidable*: Python has no built-in asymmetric crypto or AES.
  Provides RSA keygen, RSA-SHA256 signing (PKCS#1 v1.5 = A005 / PSS = A006), RSA enc/dec of the
  transaction key, AES-128-CBC for order data, and the at-rest keyring encryption (so no separate storage
  dep). *Discarded alternatives:* `pycryptodome` (capable, but `cryptography` is the more-vetted ecosystem
  standard — no reason to mix); pure-Python `rsa`+`pyaes` (slow, less audited, side-channel risk).
- **`lxml`** (BSD) — needed specifically for **Exclusive XML Canonicalization 1.0** (`xml-exc-c14n#`) via
  libxml2 (`tostring(method="c14n", exclusive=True)`); also builds/parses the H005 envelopes and camt.053.
  *Discarded alternatives:* **stdlib `xml.etree`** — its `canonicalize()` is **C14N 2.0**, a *different*
  algorithm with no `exclusive` option (verified on Python 3.14); feeding it into the DSig yields wrong
  bytes → rejected signature. `signxml`/`xmlsec` — add deps/abstraction (xmlsec needs a system C lib) and
  fight EBICS's signing quirks; we assemble the DSig ourselves. Hand-rolled exc-c14n — the classic DIY
  failure point; use libxml2.

### Optional extras (opt-in, runtime-detected — never a hard dep)

- **`pdf = ["reportlab"]`** (BSD ✅) — richer/headless INI-letter output. `make_ini_letter()` lazily tries
  to import it: present → PDF, absent → HTML + a log hint to `pip install ebicsclient[pdf]`. The letter is a
  one-off onboarding artifact, so a permanent PDF dependency would be pure waste; the core install stays at
  two deps. `reportlab` chosen over `fpdf2` (LGPL) / `borb` (AGPL) — license — and over `weasyprint` (heavy
  native libs that fail to install cleanly). Main use case: headless onboarding (no browser to "Save as PDF").

### Standard library (zero added deps)

| Module | Purpose |
|---|---|
| `urllib.request` + `ssl` | HTTPS POST to the endpoint. EBICS security is in the *payload*, not transport — one server-auth'd POST, no sessions. **Not** `requests`/`httpx` (would drag in urllib3/certifi/idna for zero benefit; `ssl.SSLContext` covers client-cert mTLS if ever needed). |
| `zlib` | Deflate/inflate of order data. EBICS mandates **deflate** — note we do *not* use Python 3.14's new `compression.zstd`. |
| `base64` | `<OrderData>` and key-blob encoding. |
| `hashlib` | SHA-256 digests (signed-info digest, pubkey hashes for INI letter / HPB verify). |
| `secrets` / `os.urandom` | Secure AES transaction key + IV, request Nonce. |
| `datetime`, `dataclasses`, `enum`, `typing`, `pathlib`, `logging` | Header timestamps, models, registries, paths, diagnostics. |

Also deliberately avoided: `keyring` (folded into `cryptography`); `defusedxml` (instead harden the lxml
parser: `resolve_entities=False`, `no_network=True`, `huge_tree=False`).

### Dev/build only (not installed by consumers)

- `pytest` (tests: sign→verify, encrypt→decrypt round-trips, camt fixtures).
- A build backend for `pyproject.toml` (`hatchling` or `setuptools`) — build-time only.

### Python version

**`requires-python = ">=3.11"`.** The hard dependency floor is **3.9** (`cryptography 49` →
`!=3.9.0,!=3.9.1,>=3.9`; `lxml` → `>=3.8`; our stdlib usage tops out at `dataclasses`/3.7). We set 3.11
rather than 3.9 because 3.9 is already EOL and 3.10 reaches EOL Oct 2026 — no current/realistic consumer
needs lower, and 3.11 lets us use modern features without supporting dead interpreters. Lower is *possible*
(down to ~3.4 with pinned-ancient deps) but pointless: a Python ≤3.3-era TLS stack can't even negotiate a
modern EBICS endpoint, and pinning a decade-old `cryptography` on a banking client is self-defeating.

*Higher* isn't justified either: nothing in 3.12/3.13 is load-bearing for us. The only tempting additions
— `typing.override` (3.12, pure type-checker hint), `itertools.batched` (3.12, a 3-line helper), f-string
PEP 701 (cosmetic), `copy.replace`/`typing.deprecated` (3.13) — are all omittable or polyfillable, and
interpreter speedups (incl. 3.13's experimental JIT) are irrelevant for a workload bound on network +
OpenSSL/libxml2 C code, not Python bytecode. So we stay at 3.11 and guard/inline any goodie rather than
raise the floor.

## Proposed module layout

The layout separates the **three axes that change on independent clocks** (see "Extension axes"
below): EBICS protocol version, business transaction (BTF/OrderSpec), and message format. Shared
modules and the public API stay version- and format-agnostic; only `protocol/` and `formats/` carry
version/format-specific code.

```
ebicsclient/
  __init__.py        # public API surface
  client.py          # orchestration — version/format-AGNOSTIC: ini(), hia(), make_ini_letter(), hpb(), download(orderspec)
  models.py          # dataclasses (Bank, User, Keyring, OrderSpec(BTF), Statement, Balance, Entry, Letter) + StrEnums (OutputFormat, ...)
  keys.py            # RSA keypair gen + encrypted keyring + pubkey hashes; plain-key now, cert identity later (don't hardcode cert-only)
  crypto.py          # auth-signature (exc-c14n + RSA-SHA256), order-data enc/dec (AES); algorithm ids come from the protocol profile, not hardcoded
  transport.py       # HTTPS POST to the EBICS endpoint — version-agnostic
  errors.py          # EBICS return-code handling
  protocol/          # everything that differs per EBICS VERSION (keyed by H-schema id)
    __init__.py      #   get_protocol("H005") -> ProtocolProfile  (registry; default = current recommended version)
    base.py          #   minimal Protocol contract that client.py depends on (build init/segment/receipt request, parse response, expose profile)
    h005.py          #   H005 envelope + profile: namespace, BTF scheme, crypto ids (auth X002 / enc E002 / sig A005|A006), plain-key|cert mode
    #                #   h004.py / h006.py — future; each self-contained + registered, no edits elsewhere
  formats/           # message-format PARSERS, decoupled from transport + protocol version
    __init__.py      #   get_parser("camt.053.001.08") -> Parser -> normalized models
    base.py          #   Parser interface -> Statement/Balance/Entry
    camt053.py       #   camt.053.001.08 now; new vintages (.09/.12) and types (camt052/054, mt940, pain001) added beside it
```

## Build order (each step independently testable)

1. **`keys.py`** — generate the three RSA keypairs; persist to an encrypted keyring file; compute the
   SHA-256 public-key hashes (needed for the init letter and for HPB verification).
2. **`protocol/h005.py` + `crypto.py` (auth signature)** — build a signed `ebicsRequest`. **Hardest part #1:**
   exc-c14n over `authenticate="true"` nodes, SHA-256 digest, RSA-SHA256 with X002. Verify your own
   signature round-trips before talking to the bank. (Define `protocol/base.py` from H005's real needs as
   you go — don't invent methods H005 doesn't use.)
3. **INI + HIA** (`client.ini()`, `client.hia()`) — `ebicsUnsecuredRequest` carrying the signature pubkey
   (INI) and auth+enc pubkeys (HIA). Send to ZKB **test platform** first.
4. **`make_ini_letter(output_format: OutputFormat = OutputFormat.AUTO)`** — render the INI + HIA
   Initialisierungsbriefe (IDs, key version, modulus/exponent hex, SHA-256 hash, signature line). Default
   output is **self-contained HTML** (stdlib string formatting, zero deps) — print from a browser, "Save as
   PDF" if wanted. **PDF is an opt-in extra:** `OutputFormat.AUTO` emits PDF iff `reportlab` (the `[pdf]`
   extra, BSD) is importable else HTML; `OutputFormat.PDF` raises a clear install-hint error if it's missing;
   `OutputFormat.HTML` always HTML. (`OutputFormat` is a `StrEnum` in `models.py`; the parameter is
   `output_format`, not `format`, which would shadow a builtin.) No PDF lib in the core — the
   letter is a one-off, so a permanent dep would be waste, and the copyleft options (`fpdf2`/`borb`) are
   banned anyway. The bank only needs a printable, hand-signed paper letter with the right hashes.
   *(This unblocks the physical onboarding — see doc 05. Do it early.)*
5. **`HPB`** (`client.hpb()`) — download bank pubkeys; **verify against the hashes on p.2 of the ZKB
   Bankparameterdaten letter** (stored in the workspace `../local/`, outside the repo).
6. **`crypto.py` (decryption)** — **Hardest part #2:** decrypt the transaction key with E002 private key,
   AES-128-CBC decrypt order data, inflate.
7. **`client.download()`** — full 3-phase download (init → transfer segments → receipt) driven by an
   `OrderSpec` carrying the `EOP/CH/ZIP/camt.053/08` BTF.
8. **`formats/camt053.py`** — parse closing balances (`Bal` `Cd=CLBD` per IBAN) + entries.

## Extension axes (deliberately deferred — design the seam, don't build it)

We implement **only H005 + `EOP/camt.053.001.08`** now, but the layout above leaves clean seams so
each likely future need is "drop in a module + register it," never a refactor. Three axes change on
**independent clocks** — keep them decoupled:

1. **EBICS protocol version** — 2.4→H003, 2.5→H004, 3.0→**H005**; a future EBICS 4.0 would *plausibly*
   be **H006**. Dispatch by the **H-schema id string** (what's on the wire) via `protocol.get_protocol()`,
   never by hardcoded calls. Treat the marketing version (3.0/4.0) as profile metadata; key code off the
   schema id. Nothing version-specific leaks into `client.py`, `crypto.py`, `transport.py`, or the public
   API (`download(orderspec)`, never `download_h005`). The selected version is config with a default that
   moves forward over time; older versions stay selectable for laggard banks.
2. **Crypto algorithm versions** — bump independently of the envelope (today auth `X002`, enc `E002`,
   sig `A005`/`A006`; a future protocol could add `X003`/`E003`/`A007`). `crypto.py` reads these ids from
   the active protocol profile rather than hardcoding them.
3. **Message format** — ISO 20022 vintages evolve on their own schedule (camt.053.001.**08** → .09 → .12),
   and new transactions appear (camt.052/054, MT940, pain.001). `formats/` is its own axis with a parser
   registry, so a new vintage never touches protocol code and a new protocol never touches parsers.

**Decisions recorded:**

- **Do not implement H004 (EBICS 2.5).** ZKB requires H005 (no H004 path exists for our first consumer),
  and H004 drags in a different signature/key model plus the dying 2009/MT formats. Globally H004 is still
  "valid" in the EBICS lifecycle and lingers in DE on legacy connections, but the momentum (mandatory
  Verification of Payee since Oct 2025; ISO 20022 "2009" switch-off 14/21 Nov 2026) is entirely toward
  H005. We leave the `protocol/` seam so an `h004.py` *could* be added if a future bank ever forces it.
- **Do not pre-build H006 / EBICS 4.** No spec exists yet — a speculative interface would be guesswork.
  Define `protocol/base.py` from H005's **real** needs only; extend the contract when H006 actually ships.
- **Key identity is a swappable mode.** CH/ZKB allows **plain keys** for download (what we build); DE/FR
  H005 generally mandates **X.509 certificates**. `keys.py` must not assume cert-only.

## Test strategy

- **ZKB test platform** (`testplattform.zkb.ch`) for protocol validation before production.
- Unit-test crypto in isolation: sign→verify, encrypt→decrypt round-trips.
- Capture a real camt.053.001.08 sample for parser fixtures.
- Use `ebics-client-php` only to **compare behavior / sanity-check** signature & encryption output —
  do **not** copy its code (licensing — doc 02).

## The two failure-prone areas (re-stated)

1. **Auth signature canonicalization** — must be byte-exact exclusive C14N of the `authenticate="true"`
   subset. Most DIY failures are here.
2. **Order-data crypto** — exact AES mode/padding + EBICS transaction-key handling.

## Downstream integration

The downstream app (`downstream app`, Django backend) consumes this as a dependency for its ZKB broker:
call `download()` (EOP/camt.053 OrderSpec) on the sync schedule, parse, store balances alongside
various accounts.
