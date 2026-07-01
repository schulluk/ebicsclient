# Engineering conventions

## Why this bar exists — read first

**This software moves money.** It talks to banks: today it reads statements, eventually it initiates
payments, and even the read-only MVP handles live credentials and account data. **Correctness and security
*are* the product** — a banking library is only worth anything if it's trusted, and trust is destroyed by
sloppiness long before it's destroyed by a missing feature.

Therefore the conventions below are **not stylistic preferences — they are the trust contract**, and they
apply from the first line, including in the read-only MVP (shortcuts compound and are rarely revisited).
Anything that quietly erodes trust is unacceptable: magic strings instead of enums (`output_format='html'`),
missing type hints, absent or filler docstrings, unvalidated input, swallowed errors, abbreviated/vague
names, secrets in logs. There is no "fine for now" on a money-moving codebase. When in doubt, choose the
more explicit, more defensive, more auditable option.

---

Baseline practices decided **before** writing code so we don't retrofit them into a mess. They follow the
project's values: minimal dependencies, security-first (this is a banking client), licensing hygiene for the
source-available/commercial model, and scope discipline. **[now]** = cheap and painful to retrofit, do it
with the first code; **[soon]** = add as the surface grows.

## Packaging & layout

- **[now] `src/` layout** — code lives in `src/ebicsclient/`. Prevents importing the un-installed package by
  accident; tests run against the installed artifact, not the working tree.
- **[now] `pyproject.toml`** (PEP 621) with a single build backend — **`hatchling`**. One source of truth.
- **[now] Version single-sourced** — e.g. `__version__` via `importlib.metadata`, or `hatch-vcs` from git
  tags. Never hand-duplicate the version string.
- **[now] Ship `py.typed`** (PEP 561) so consumers receive our type hints.
- **[now] Small, curated public API** — `ebicsclient/__init__.py` exposes a deliberate surface via `__all__`;
  everything else is internal. The public API stays **protocol/format-agnostic** (see doc 04 extension axes):
  `download(orderspec)`, never `download_h005`.

## Dependencies

- **Runtime:** `cryptography` + `lxml` only (doc 04). Nothing else ships by default.
- **Optional extras** — opt-in, lazily imported, graceful fallback + a log hint when absent:
  - `pdf = ["reportlab"]` (BSD) → richer/headless INI-letter output; absent → HTML.
- **Dev-only (never shipped):** `pytest`, `ruff`, `mypy` (or `pyright`), and a build backend.
- Licenses stay permissive (BSD/Apache/MIT). No GPL/AGPL/LGPL — even as an optional extra.

## Logging

- Stdlib `logging`. Per-module `logger = logging.getLogger(__name__)` → an `ebicsclient.*` hierarchy
  consumers can filter.
- **The library never configures logging** — no `basicConfig`, no root handlers, no level-setting. That is
  the application's job. Add exactly one `logging.NullHandler()` to the `ebicsclient` logger in `__init__.py`.
- Levels: **DEBUG** = wire/protocol detail; **INFO** = high-level steps (INI sent, N segments fetched);
  **WARNING** = recoverable oddities; **ERROR** = failures.
- **Never log secrets.** No private keys, passphrase, transaction keys, or raw decrypted order data.
  Wire-level XML dumps can carry sensitive data → DEBUG-only, behind an explicit opt-in flag, key material
  redacted. This is a security rule, not a style choice.

## Errors

- One hierarchy rooted at **`EbicsError`** (`errors.py`). Subtypes: `TransportError`, `ProtocolError`,
  `CryptoError`, `ReturnCodeError` (carries the EBICS return code + text). Consumers catch the base.
- **Fail closed** — never catch-and-swallow a crypto/verification failure.
- **Granularity by failure mode, not by call direction.** Split an error type only when the caller would
  *act differently*. The function name already tells you which operation failed, so an `EncodeError` vs
  `DecodeError` split adds nothing — but `KeyringDecryptionError` vs `KeyringFormatError` does, because one
  is fixed by a new passphrase and the other is not. Keep new subtypes under their existing base so coarse
  `except` handlers keep working.

### Retryable vs permanent

Every error declares **how a retry could help**, via `EbicsError.retryability` (a `Retryability`
`StrEnum`), so retry loops and user interfaces never have to match on error text. The three states are
deliberately distinct — conflating them is unsafe:

- **`PERMANENT`** (the default) — retrying never helps; surface it. Malformed data, unsupported
  version/format, a permanently rejected user, programmer errors. E.g. `KeyringFormatError`.
- **`CORRECTABLE`** — a retry succeeds only after the *caller corrects the input*; **prompt, never
  auto-retry**. A wrong passphrase (`KeyringDecryptionError`) is the canonical case.
- **`TRANSIENT`** — safe to **auto-retry the same call** after a backoff: network timeouts, HTTP 5xx,
  EBICS recovery/synchronisation return codes. **Only this state is eligible for automatic retry.**

Rules: default to `PERMANENT` (fail closed); promote to `TRANSIENT` only when a retry is genuinely safe —
and for **write** operations (uploads) that additionally requires the request to be **idempotent**, so an
auto-retry can't double-submit. Set `retryability` per-instance when it depends on context (e.g. the
specific return code on `ReturnCodeError`).

## Configuration & credentials

- **The library never reads ambient config.** No `os.environ`, no auto-loaded `.env`, no hunting for files.
  Credentials and connection details enter *only* as explicit typed config — `Bank`, `User`, `Keyring`
  (keyring = a caller-supplied file path + a passphrase string or callback). The library reads exactly what
  it is handed.
- **Gathering** those values from env vars / a vault / Django settings is the **consumer's** job, never the
  library's. Explicit config is auditable; silent environment reads are a surprise and a leakage footgun on a
  money-moving codebase.

## Security (banking client — non-negotiable)

- Keyring **encrypted at rest**; passphrase supplied explicitly by the caller (string or callback),
  **never hardcoded or committed** (the *caller* may source it from env — the library does not read env).
- Real credentials live in the workspace `../local/` **outside** the repo (can't be committed). The repo
  `.gitignore` still covers `*.pem`, `*.key`, keyring files, and `local/` as defense-in-depth.
- **`hmac.compare_digest`** for HPB public-key-hash verification (constant-time).
- **Harden the lxml parser:** `resolve_entities=False`, `no_network=True`, `huge_tree=False`
  (XXE / billion-laughs / SSRF defense) on every parse of bank or camt XML.
- **TLS ≥ 1.2** enforced on the `ssl` context; keep default certificate verification on.

## Naming

- **Spell names out — no abbreviations.** `output_format`, not `fmt`; `signature`, not `sig`;
  `transaction`, not `txn`. Full words cost nothing and read better. (Domain-standard initialisms that
  *are* the canonical term — EBICS, BTF, IBAN, RSA, AES, INI/HIA/HPB, camt — stay as-is.)
- **One exception:** when a full name would shadow a builtin or keyword, don't truncate — qualify it.
  Prefer `output_format` over `format`, `input_type` over `type`. A trailing underscore (`id_`) is a last
  resort, not the default.

## Typing

- **Every function and method is fully typed** — all parameters *and* the return type. No exceptions; CI
  enforces it with **`mypy --strict`** (or pyright strict). Ship `py.typed` so consumers get the hints.
- **Enums, not magic strings, for any closed value set.** Use **`StrEnum`** (stdlib, 3.11+) for
  string-valued sets — members are real strings (clean logging/serialization) yet type-checked. Accept the
  enum in signatures, not bare `str`. Example: `output_format: OutputFormat = OutputFormat.AUTO`.
- **No `from __future__ import annotations`.** The 3.11+ floor supports `X | Y` (PEP 604) and `list[x]`
  (PEP 585) natively, so the import is unnecessary boilerplate. If a single module genuinely needs a
  forward reference, quote that one annotation (`"Keyring"`) rather than adding the blanket future-import.

## Docstrings

Every function and method has a docstring (Google-style):

- **A one-line summary that says something** — what it does and why it matters. No filler, no restating the
  name ("Makes the INI letter." adds nothing).
- **`Args:`** — each parameter, what it means (not its type — that's in the signature).
- **`Returns:`** — what comes back and in what shape.
- **`Raises:`** — only when the function actually raises; name the exception and the trigger condition.

```python
def make_ini_letter(output_format: OutputFormat = OutputFormat.AUTO) -> Letter:
    """Render the INI + HIA initialisation letters for hand-signing and mailing.

    Args:
        output_format: AUTO emits PDF when the [pdf] extra is installed, else HTML.

    Returns:
        The rendered letter — content bytes plus media type.

    Raises:
        MissingDependencyError: output_format is PDF but reportlab isn't installed.
    """
```

## Lint & format

- **`ruff`** for lint + format (one tool, replaces black/isort/flake8). Config in `pyproject.toml`.

## Testing

**Verification discipline — the rule that would have caught the c14n bug.** Protocol correctness is a
*specification* question. A wrong-but-self-consistent implementation passes every round-trip test, which
is exactly how the project initially shipped exclusive c14n instead of the mandated inclusive C14N 1.0
(post-mortem in [doc 08](08-parity-and-xsd-findings.md)). Therefore:

- **Cite the normative source** for every protocol constant/structure (namespace, algorithm URI, element
  name, order type, encoding): the H005 XSD or an EBICS spec section — never "how XML/crypto usually
  works" and never another client. Uncited protocol claims are TODOs, not facts.
- **No wire-format layer is "done" until validated against an external oracle**, because round-trips prove
  consistency, never interoperability. Use the XSD (`python tools/fetch-schemas.py` +
  `tests/test_schema_validation.py`), published spec vectors, or a second implementation
  (`tools/php-parity/`). **Golden vectors must come from that authority, never hand-derived from our own
  output** (a mirror can't falsify the belief it reflects).
- **Verify foundations earliest** — the more foundational the choice (algorithm, namespace, message
  shape), the sooner it must be schema-checked; those errors propagate furthest.

Two tiers:

- **Unit (the bulk; runs in CI; no credentials).** Ephemeral generated keys, static fixtures, recorded
  responses — **CI never touches the live bank.**
  - Crypto: round-trip tests (sign→verify, encrypt→decrypt) — for *consistency*, paired with an external
    oracle for *correctness*.
  - **Canonicalization (the #1 failure point):** golden vectors derived from the C14N spec, plus
    cross-implementation parity against `ebics-client-php` (**without copying its code**, doc 02) and
    schema validation. The mandated algorithm is inclusive Canonical XML 1.0 (`REC-xml-c14n-20010315`).
  - **Structure:** validate INI/HIA/HPB envelopes and order data against the H005 XSDs.
  - camt parsing: a sanitized real `camt.053.001.08` sample as a fixture.
- **Integration (local-only, opt-in, never in CI).** Hits the **ZKB test platform** (testplattform.zkb.ch).
  - Marked `@pytest.mark.integration`, **excluded by default** (`-m "not integration"`); run with `-m integration`.
  - `conftest.py` gathers credentials from env (`EBICS_HOST_ID`, `EBICS_PARTNER_ID`, `EBICS_USER_ID`,
    `EBICS_KEYRING_PATH`, `EBICS_KEYRING_PASSPHRASE`) via stdlib `os.environ` and `pytest.skip(...)`s when any
    are missing — so contributors without creds skip cleanly. Key *material* stays in the encrypted keyring
    file; env carries only the path, passphrase, and IDs. Credentials are never logged.

**Test/dev tooling goes in PEP 735 `[dependency-groups]`, not a published extra.** Extras
(`[project.optional-dependencies]`) are consumer-facing *features* (e.g. `[pdf]`); a `[test]` extra would be
a category error — end users don't install your test suite. Env-var handling needs no dependency (stdlib
`os.environ`); `python-dotenv` (BSD) may sit in the `test` group purely as ergonomic sugar to load the
workspace `../local/.env` (outside the repo).

```toml
[dependency-groups]
test = ["pytest", "python-dotenv"]
dev  = ["ruff", "mypy", {include-group = "test"}]
```

"Not published" means these don't ship in the wheel/sdist end users install — **not** that contributors
can't get them. The `pyproject.toml` is in the repo, so anyone who clones installs them in one command
(`uv sync --all-groups`, or `pip install -e . --group dev` on pip >= 25.1). Contributor setup steps live in
[CONTRIBUTING.md](../CONTRIBUTING.md); recommend `uv` (no pip-version floor) with pip as the fallback.

## Versioning, changelog, CI

- SemVer. `CHANGELOG.md` (Keep a Changelog format). Keep the README "Status" current (per CLAUDE.md).
- Dual-license `LICENSE` with SPDX headers (doc 02).
- **[soon]** Lightweight GitHub Actions: `ruff` + `mypy` + `pytest` across Python 3.11 / 3.12 / 3.13.
  No live-bank calls.
