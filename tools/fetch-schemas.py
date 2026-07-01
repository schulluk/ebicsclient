"""Fetch the EBICS H005 XSD schemas for the offline schema-validation tests.

The schemas are published by the EBICS working group; this downloads a mirror into
``tests/schema/H005/`` (gitignored — we do not redistribute them). Run it once to enable
``tests/test_schema_validation.py``, which validates our requests against the authoritative
structure:

    python tools/fetch-schemas.py

CI should run this before pytest so the schema checks are not silently skipped.
"""

import subprocess
from pathlib import Path

_MIRROR = "https://raw.githubusercontent.com/ebics-api/ebics-client-php/3.x/doc/schema/H005"
_FILES = (
    "ebics_H005.xsd",
    "ebics_keymgmt_request_H005.xsd",
    "ebics_keymgmt_response_H005.xsd",
    "ebics_orders_H005.xsd",
    "ebics_request_H005.xsd",
    "ebics_response_H005.xsd",
    "ebics_signature_S002.xsd",
    "ebics_types_H005.xsd",
    "xmldsig-core-schema.xsd",
)
_DESTINATION = Path(__file__).resolve().parent.parent / "tests" / "schema" / "H005"


def main() -> None:
    """Download every H005 schema file into the destination directory.

    Uses ``curl`` (which respects the system trust store) rather than urllib, whose
    framework-Python build on macOS often cannot verify TLS certificates.
    """
    _DESTINATION.mkdir(parents=True, exist_ok=True)
    for name in _FILES:
        url = f"{_MIRROR}/{name}"
        subprocess.run(["curl", "-sSf", "-o", str(_DESTINATION / name), url], check=True)
        print(f"fetched {name}")
    print(f"H005 schemas written to {_DESTINATION}")


if __name__ == "__main__":
    main()
