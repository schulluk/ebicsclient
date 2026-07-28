# Examples

Small, runnable scripts, each focused on a single scenario so you can see *why* you'd reach
for a feature, not just how to call it. They are configured entirely through `EBICS_*`
environment variables (load them from a dotenv file **outside** the repo); no example ever
contains credentials. The shared setup — reading those variables, loading the keyring,
building the client, running HPB — lives in [`_config.py`](_config.py), so each example stays
focused on its own idea.

## Before running

You need an initialised, activated subscriber and an encrypted keyring. The full onboarding
ceremony (generate keys → INI → HIA → sign the letter → HPB) is driven by
[`zkb_handshake.py`](zkb_handshake.py); start there to create the keyring and bring the
subscriber online. Then set the environment variables listed at the top of
[`_config.py`](_config.py) and run any example with `uv run python examples/<file>`.

## The scripts

| Script | What it does | Feature |
|---|---|---|
| [`01_account_discovery_peek.py`](01_account_discovery_peek.py) | Downloads the waiting statements without consuming them, so a later run still gets the data. | Non-consuming read (`ReceiptPolicy.KEEP`) |
| [`02_daily_statement_sync.py`](02_daily_statement_sync.py) | Processes each statement before acknowledging, so a failure leaves the data at the bank for the next run. | Consume-safe read (acknowledge last, via the `validate` seam) |
| [`03_dated_backfill.py`](03_dated_backfill.py) | Fetches statements for a specific past date range, failing closed if the bank ignores the range. | `DateRange` + `DateRangeMismatchError` |
| [`04_pay_and_check_status.py`](04_pay_and_check_status.py) | Uploads a pain.001 batch, then downloads the pain.002 verdict — accepted, partial, or rejected down to the transaction. | Payment upload + status-report round-trip |
| [`05_certificate_profile_onboarding.py`](05_certificate_profile_onboarding.py) | Runs INI/HIA presenting CA-issued certificates instead of self-signed ones. | "mit Zertifikaten" profile (`MappingCertificateProvider`, `TrustAnchorVerifier`) |

For the complete step-by-step handshake against a live bank (every order type, one
subcommand each), see [`zkb_handshake.py`](zkb_handshake.py).
