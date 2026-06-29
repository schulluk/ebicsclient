# Contributing

Thanks for helping build `ebicsclient`. **Read this first:** this is a banking library — it handles live
credentials and will eventually move money. The bar is hardened, fully-typed, fully-documented code with no
shortcuts. The standard is [docs/06-engineering-conventions.md](docs/06-engineering-conventions.md); please
skim it before your first PR.

## Prerequisites

- Python **3.11+**
- git
- [`uv`](https://docs.astral.sh/uv/) recommended (handles venv + dependencies in one step). A plain-pip path
  is documented too.

## Set up a dev environment

### With uv (recommended)

```
git clone https://github.com/schulluk/ebicsclient && cd ebicsclient
uv sync --all-groups        # creates .venv, installs ebicsclient (editable) + all dev/test deps
```

Run tools through `uv run`:

```
uv run pytest -m "not integration"   # unit tests (no credentials needed)
uv run ruff format .                 # format
uv run ruff check .                  # lint
uv run mypy src                      # type-check (strict)
```

### With pip (requires pip >= 25.1 for PEP 735 `--group`)

```
python -m venv .venv
source .venv/bin/activate             # Windows: .venv\Scripts\activate
pip install -e . --group dev          # editable install + dev deps (includes the test group)
```

Optional PDF backend for the init letter: add the `pdf` extra, e.g. `pip install -e ".[pdf]" --group dev`.

## Running the tests

Two tiers (see doc 06):

- **Unit tests** — the default, no credentials, exactly what CI runs:
  ```
  pytest -m "not integration"
  ```
- **Integration tests** — optional, local-only, hit the **ZKB test platform**. They need credentials in the
  environment and are **skipped automatically** when those are absent:
  ```
  export EBICS_HOST_ID=...        EBICS_PARTNER_ID=...   EBICS_USER_ID=...
  export EBICS_KEYRING_PATH=...   EBICS_KEYRING_PASSPHRASE=...
  pytest -m integration
  ```
  You may instead drop these in **`../local/.env`** — the workspace credentials directory that lives *outside*
  the repo (loaded by the test harness via `python-dotenv`). **Never commit credentials or keyrings;** keeping
  them in `../local/` outside the repo is what makes that impossible.

## Before opening a PR

- `ruff format .` and `ruff check .` are clean
- `mypy --strict` passes — every function fully typed (params *and* return)
- `pytest -m "not integration"` passes
- New/changed functions have Google-style docstrings (meaningful summary + `Args` / `Returns` / `Raises`)
- No shortcuts that erode trust: enums over magic strings, validated input, errors that fail closed, no
  secrets in logs, names spelled out in full (see doc 06)

## Where things live

- Architecture, scope, build order — [docs/04-implementation-plan.md](docs/04-implementation-plan.md)
- The engineering bar — [docs/06-engineering-conventions.md](docs/06-engineering-conventions.md)
- Protocol/format background — [docs/01-protocol-and-formats.md](docs/01-protocol-and-formats.md)
- Real credentials — `../local/` in the workspace, outside the repo, never committed
