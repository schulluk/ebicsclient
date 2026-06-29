# Existing EBICS libraries

## The landscape (as of mid-2026)

| Library | Lang | H005? | License | Notes for us |
|---|---|---|---|---|
| **fintech** (joonis) | Python | ✅ full | Proprietary | Pure-Python and full-featured, but proprietary. The free tier does not retrieve statements from the last three days; full use is a paid product (setup fee + per-user monthly). Its camt parser is freely usable. |
| **ebics-client-php** | PHP | ✅ (2.4/2.5/3.0; A005/A006/E002/X002) | MIT | Free and functional, but PHP — a separate runtime alongside a Python application. Best **behavioral reference**. |
| **ebics-web-client** (spaced) | Java | ✅, Swiss support | Some lineage may be AGPL — verify | Free, but a JVM runtime; AGPL lineage would not fit our licensing. |
| **ebicsPy / PyEBICS** | Python | ❓ unverified | Open | Maturity unverified. |

No existing option is both pure-Python and openly licensed, which is the gap this library fills.

## Why we build our own

- **Stack fit:** pure Python — no PHP or JVM runtime to operate alongside a Python application.
- **Open and unrestricted:** no per-seat fees or feature gates; usable for recent statements.
- **Low maintenance:** EBICS is a stable, formally versioned standard. Scoped to download-only + camt.053,
  the surface is small and changes rarely; the occasional format/version bumps are pre-announced (we track
  the Nov 2025 / Nov 2026 deadlines).
- **Fits the downstream app pattern:** existing brokers (MS via tooling, broker Flex) are custom
  integrations; a scoped EBICS module is more standardized than any of those.
- **It becomes a product** (see [02-licensing-strategy.md](02-licensing-strategy.md)).

## The honest cost

The cost is **upfront correctness**, not ongoing churn — concentrated in (1) the auth-signature XML
canonicalization and (2) order-data encryption/decryption. Mitigate by validating against a bank test
platform and using `ebics-client-php` as a *behavioral* reference (read, don't copy — see doc 02).
Ongoing maintenance is genuinely low; per-bank quirks only multiply if/when a second bank is added.
