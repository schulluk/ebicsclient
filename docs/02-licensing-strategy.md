# Licensing strategy

## Goal

**Source-available** — ship the full source — but **require a paid license for commercial/business use**.
Free for personal/non-commercial use.

## This is viable

You own the copyright to code you write, so you may license it under any terms, including
"free for noncommercial, paid for commercial." Proven model (the `fintech`/joonis EBICS library does
exactly this; MariaDB/Sentry use time-delayed variants).

**Use a recognized source-available license, not a hand-rolled one** — legal/procurement teams can
clear a known license in minutes, which *encourages* purchase:

- **PolyForm Noncommercial** — purpose-built for "free for noncommercial, buy a license for commercial."
  Most likely match.
- **BUSL (Business Source License)** — alternative; commercial-restricted now, auto-converts to open
  source after N years.

## What a commercial license actually buys (and doesn't)

It does **not** buy lock-in. It buys **legitimacy + a vendor relationship**:

1. **Compliance** — a company's legal/procurement won't run production code under a noncommercial
   license; they need a clean paid license on file. Biggest purchase driver.
2. **Support + maintenance** — and EBICS is perfect here: live regulatory deadlines (Nov 2025, Nov 2026,
   future format bumps) mean businesses want someone accountable who ships the update. Recurring value a
   stolen copy can't provide.
3. **Cost math** — if the license is cheaper than building+maintaining EBICS themselves (crypto,
   canonicalization, per-bank quirks, the deadline treadmill), paying is rational. **The moat is the
   maintenance burden, not the law.**

Market fit is strong: buyers are banks / fintechs / ERP & accounting vendors — risk-averse,
compliance-driven orgs that reliably pay. Far better than consumer software for this model.

## The legal realities (accepted, not fought)

| Scenario | Legal status | Enforceable? |
|---|---|---|
| Copy/translate your code, use commercially | Infringement (violates license) | **Yes** — real standing |
| Run your code commercially without a license | Infringement | **Yes** |
| **Clean reimplementation** from the EBICS spec | **Generally legal** | **No** |

Key point: copyright protects your **expression** (the code), **not** functionality, methods, or the
EBICS protocol — that's a public standard anyone may implement. So you **cannot** stop someone from
writing their own EBICS client. Anti-reimplementation license clauses are weak (bind only accepted
licensees) and against the source-available spirit — don't bother. The grey zone: a "reimplementation"
that copies your *expression* (structure, non-obvious design, naming, comments) is a derivative and
infringes; a genuine from-spec rewrite is clean.

## Low-fight posture

- Recognized license (PolyForm Noncommercial), priced **cheap + frictionless** — overpricing/friction
  pushes people to reimplement or pirate.
- Sell the **relationship**: updates, deadline-tracking, support, optional indemnification.
- **No DRM/obfuscation/license keys** — pointless for source-available; accept some leakage.
- Enforcement = a polite email to non-compliant businesses; they fold fast on legal risk. Litigation
  reserved for egregious cases (rarely needed).

## Implication for our own dependencies & references

- Keep **all dependencies permissive** (BSD/Apache/MIT): `cryptography`, `lxml` are fine. **Never add a
  GPL/AGPL dependency** — copyleft would force open-sourcing / break the commercial model.
- `ebics-client-php` is **MIT** → you *may* legally read, reuse, even sell derivatives, provided you
  preserve its MIT notice for any copied parts. **But** to keep our license fully unencumbered, treat it
  as a *behavioral reference only* — implement from the spec, don't copy its expression. Then we owe no
  attribution and control 100% of the licensing.
- Some Java EBICS clients are AGPL — do **not** port from those.

> Not legal advice — have a lawyer review the final license + any attribution before the first sale.
