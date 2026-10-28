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
[`_config.py`](_config.py) and run any example with `uv run python examples/<file>`. To run
them against another subscriber, for example the PostFinance test platform, point
`EBICS_ENV_FILE` at that subscriber's dotenv file.

## The scripts

| Script | What it does | Feature |
|---|---|---|
| [`01_account_discovery_peek.py`](01_account_discovery_peek.py) | Downloads the waiting statements without consuming them, so a later run still gets the data. | Non-consuming read (`ReceiptPolicy.KEEP`) |
| [`02_daily_statement_sync.py`](02_daily_statement_sync.py) | Processes each statement before acknowledging, so a failure leaves the data at the bank for the next run. | Consume-safe read (acknowledge last, via the `validate` seam) |
| [`03_dated_backfill.py`](03_dated_backfill.py) | Fetches statements for a specific past date range, failing closed if the bank ignores the range. | `DateRange` + `DateRangeMismatchError` |
| [`04_pay_and_check_status.py`](04_pay_and_check_status.py) | Uploads a pain.001 batch, then downloads the pain.002 verdict — accepted, partial, or rejected down to the transaction. | Payment upload + status-report round-trip |
| [`05_certificate_profile_onboarding.py`](05_certificate_profile_onboarding.py) | Runs INI/HIA presenting CA-issued certificates instead of self-signed ones. | "mit Zertifikaten" profile (`MappingCertificateProvider`, `TrustAnchorVerifier`) |
| [`06_key_rotation.py`](06_key_rotation.py) | Replaces all three keys at the bank without a letter, storing the new keyring so neither set can be lost. | Key change (`HCS`, `change_keys`, `rotate_keyring`) |
| [`07_incoming_payments.py`](07_incoming_payments.py) | Resolves a collective credit into its single payments and groups the day's incoming payments by creditor reference, the key an invoice is matched on. | `Entry.transactions` (`TransactionDetails`) from camt.054 booking advices |
| [`08_bank_discovery.py`](08_bank_discovery.py) | Asks the bank what it offers: EBICS versions before onboarding, then parameters, registered order types with signature requirements, waiting data, and the registered form of the pain.002 download. | HEV, HPD, HTD, HAA |
| [`09_audit_trail_hac.py`](09_audit_trail_hac.py) | Reads the bank's log of EBICS actions and tells per order whether the signatures were verified and how the order was closed. | Customer acknowledgement (`HAC`) |
| [`10_strict_message_version.py`](10_strict_message_version.py) | Downloads statements under the strict version policy, so a document in another message version fails closed and stays at the bank instead of being consumed. | `VersionPolicy.STRICT`, `MessageVersionMismatchError` |

For the complete step-by-step handshake against a live bank (every order type, one
subcommand each), see [`zkb_handshake.py`](zkb_handshake.py).
