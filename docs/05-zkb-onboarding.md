# ZKB onboarding — the init ceremony

ZKB recommends **EBICS 3.0 (H005)**. Before any download, a subscriber's keys must be initialised at the
bank. Activation is **purely via hand-signed paper init letters**; there is **no transport password /
activation PIN**.

> Real connection parameters (Host ID, Partner/User ID, bank-key hashes) live in the workspace `../local/`
> directory **outside** this repo, taken from the ZKB *Bankparameterdaten* letter. Never commit them.

## The ceremony (long pole — involves physical mail; start early)

1. **Generate** your three RSA keypairs (A006 sig, X002 auth, E002 enc) → encrypted keyring.
2. **INI** — send your signature public key (`ebicsUnsecuredRequest`, order type `INI`).
3. **HIA** — send your authentication + encryption public keys (order type `HIA`).
4. **Initialisierungsbriefe** — `make_ini_letter()` renders the INI + HIA letters as **printable HTML**
   (no PDF dependency — see doc 04; print from a browser, "Save as PDF" if you want a file) containing the
   SHA-256 hashes of *your* public keys. **Sign them by hand (legally valid signature)** and mail to ZKB
   Kompetenzcenter Services. ZKB verifies the signature against documents on file, then activates and
   confirms your access.
5. **HPB** — download ZKB's public keys and **verify them against the hashes printed on p.2 of the
   Bankparameterdaten letter** (in `../local/`).
6. **Download** statements via the `EOP/camt.053.001.08` BTF.

Steps 1–4 (up to printing the letters) can be built and tested **without** waiting on ZKB — do them
against the test platform first. Step 5 onward needs ZKB to have activated you.

## Order types / BTF (ZKB Bankparameterdaten)

- **Submission** (key mgmt): `HCA`, `HCS`, `HIA`, `INI`, `PUB`, `SPR`.
- **Download**: `HAA`, `HAC`, `HKD`, `HPB`, `HPD`, `HTD`, `PTK`, plus the BTF business transactions.
- **The one we use** — statement download BTF:

  | Field | Value |
  |---|---|
  | Service Name | `EOP` |
  | Scope | `CH` |
  | Container | `ZIP` |
  | Message Name | `camt.053` |
  | Message Version | `08` |

  (camt.052 intraday → `STM`/`camt.052`/`08`; camt.054 → `REP`/`camt.054`/`08`. Everything `_04` /
  `STA` / `VMK` / `Z5x` / MT940 is the legacy 2009/MT format dying 21 Nov 2026 — do not use.)

## Open (non-blocking) questions for ZKB

Contact: **support.epayment@zkb.ch / +41 44 293 99 15** (Kompetenzcenter Services).

- Confirm **plain keys** ("mit Schlüsseln") are fine for download-only — assume yes, proceed.
- Profile **T** (no distributed signature) — irrelevant since download-only.
