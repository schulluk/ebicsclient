# Examples

Small, runnable scripts — each one tells a short story around a single scenario, so you can
see *why* you'd reach for a feature, not just how to call it. They are configured entirely
through `EBICS_*` environment variables (load them from a dotenv file **outside** the repo);
no example ever contains credentials. The shared setup — reading those variables, loading the
keyring, building the client, running HPB — lives in [`_config.py`](_config.py), so each
example stays focused on its own idea.

## Before running

You need an initialised, activated subscriber and an encrypted keyring. The full onboarding
ceremony (generate keys → INI → HIA → sign the letter → HPB) is driven by
[`zkb_handshake.py`](zkb_handshake.py); start there to create the keyring and bring the
subscriber online. Then set the environment variables listed at the top of
[`_config.py`](_config.py) and run any example with `uv run python examples/<file>`.

## The scripts

| Script | The story | Feature |
|---|---|---|
| [`01_account_discovery_peek.py`](01_account_discovery_peek.py) | An ops engineer checks what a newly wired-up account will deliver — without consuming it, so tonight's real import still gets everything. | Non-consuming read (`ReceiptPolicy.KEEP`) |
| [`02_daily_statement_sync.py`](02_daily_statement_sync.py) | A nightly job books each statement into the ledger and only *then* lets the bank mark the data delivered — a failure leaves it at the bank for the next run. | Consume-safe read (acknowledge last, via the `validate` seam) |
| [`03_dated_backfill.py`](03_dated_backfill.py) | Bootstrapping an empty tool needs the back-history: fetch a specific past quarter, and fail closed if the bank ignores the requested range. | `DateRange` + `DateRangeMismatchError` |
| [`04_pay_and_check_status.py`](04_pay_and_check_status.py) | Supplier-payment day: submit a pain.001 batch, then come back for the bank's pain.002 verdict — accepted, partial, or rejected down to the transaction. | Payment upload + status-report round-trip |
| [`05_certificate_profile_onboarding.py`](05_certificate_profile_onboarding.py) | A corporate PKI issues CA-signed certificates for the three keys; onboarding presents those instead of self-signed ones. | "mit Zertifikaten" profile (`MappingCertificateProvider`, `TrustAnchorVerifier`) |

For the complete step-by-step handshake against a live bank (every order type, one
subcommand each), see [`zkb_handshake.py`](zkb_handshake.py).
