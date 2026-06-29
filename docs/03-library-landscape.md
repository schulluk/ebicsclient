# Existing EBICS libraries & why DIY

## The landscape (as of mid-2026)

| Library | Lang | H005? | License | Cost | Verdict for us |
|---|---|---|---|---|---|
| **fintech** (joonis) | Python | ✅ full | Proprietary | **Free tier blocks last-3-days statements**; full = €100 setup + €25/mo/user | Pure-Python but the free gate makes data always ≥3 days stale; paid defeats the point |
| **ebics-client-php** | PHP | ✅ (2.4/2.5/3.0, A005/A006/E002/X002) | **MIT** | Free, no limits | Fully free + functional, but PHP → foreign-runtime sidecar in our Python stack. Best **reference**. |
| **ebics-web-client** (spaced) | Java | ✅, Swiss support | (check — some lineage is AGPL) | Free | Heavy JVM sidecar; AGPL risk if porting |
| **ebicsPy / PyEBICS** | Python | ❓ unverified | open | Free | Low maturity; risky to depend on |

## The fintech free-tier trap (important)

`fintech`'s only binding restriction for our use case is: **"Bank account statements can not be retrieved
for the last three days."** (The SEPA-upload cap and EDS lockout don't affect download-only use.) So free
= balances always ~3 days stale. The 3-day limit is **fintech's own client-side gate, not a bank rule** —
ZKB doesn't care what software you use. But you **can't** use fintech as the engine and bypass the gate:
the limit lives inside the exact statement-download code path, there's no clean "give me the signed request
bytes" seam, and the package is obfuscated/license-locked to prevent patching it out. You *can* legitimately
use fintech's **free, ungated camt parser** — but not its download engine sans-gate.

## Why implement our own

- **Stack fit:** pure Python, no PHP/Java sidecar to operate alongside Django.
- **Free + fresh:** no 3-day gate, no fees.
- **Low maintenance:** EBICS is a stable, formally-versioned standard. Scoped to one bank + download-only
  + camt.053, the surface is small and changes rarely (the rare format/version bumps are pre-announced —
  we already track Nov 2025 / Nov 2026).
- **Fits the downstream app pattern:** existing brokers (MS GraphQL via tooling, broker Flex) are custom
  reverse-engineered integrations; a scoped EBICS module is *more* standardized than any of those.
- **It becomes a product** (see [02-licensing-strategy.md](02-licensing-strategy.md)).

## The honest cost

The cost is **upfront correctness**, not ongoing churn — concentrated in (1) the auth-signature XML
canonicalization and (2) order-data encryption/decryption. Mitigate by validating against ZKB's test
platform and using `ebics-client-php` as a *behavioral* reference (read, don't copy — see doc 02).
Ongoing maintenance is genuinely low; per-bank quirks only multiply if/when a second bank is added.
