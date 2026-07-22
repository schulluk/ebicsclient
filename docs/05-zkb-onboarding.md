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
4. **Initialisierungsbriefe** — `make_ini_letter()` renders **both** EBICS 3.0 letters (the INI
   letter with the A006 signature certificate; the HIA letter with the X002 and E002 certificates,
   on its own page) as **printable HTML** by default (no dependency) or as **PDF** with the optional
   `pdf` extra; `AUTO` picks PDF when that extra is installed, else HTML. Per the EBICS 3.0 spec
   (section 4.4.1.2.3) each letter shows the certificate in PEM **and the SHA-256 hash of its DER
   encoding** in uppercase hex — *not* the EBICS 2.x public-key (`exponent modulus`) hash; the bank
   compares those fingerprints against the certificates it received over INI/HIA. The default
   self-signed certificates are **deterministic**, so the letter always reproduces exactly the
   certificates the requests transmitted, from the keyring alone. **Sign each page by hand (legally
   valid signature)** and mail to ZKB Kompetenzcenter Services. ZKB verifies the signature against
   documents on file, then activates and confirms your access. See
   [doc 07](07-handshake-testing.md) for the end-to-end test walkthrough.
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

## Production watch-item: `BankPubKeyDigests` hash format

The EBICS 3.0 spec (section 5.5.1.1) defines the `BankPubKeyDigests` values in requests as the
SHA-256 over the bank **certificate's DER** — but this client sends the EBICS 2.x public-key
(`exponent modulus`) digest, and the ZKB **test platform accepted that in every live
transaction** (downloads and uploads). ZKB's published Bankparameterdaten hashes are also
public-key hashes, so HPB pinning stays in the `e m` format. If ZKB **production** ever rejects
requests with `EBICS_BANK_PUBKEY_UPDATE_REQUIRED` despite fresh HPB keys, this mismatch is the
first suspect: the fix is to retain the bank *certificates* from the HPB response and send
their DER SHA-256 fingerprints instead.
