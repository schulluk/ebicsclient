"""Fetch the EBICS XSD schemas for the offline schema-validation tests.

The schemas are published by the EBICS working group; this downloads a mirror into
``tests/schema/H005/`` and, for the version-independent HEV request, ``tests/schema/H000/``
(gitignored — we do not redistribute them). Run it once to enable
``tests/test_schema_validation.py``, which validates our requests against the authoritative
structure:

    python tools/fetch-schemas.py

CI should run this before pytest so the schema checks are not silently skipped.
"""

import subprocess
from pathlib import Path

_MIRROR = "https://raw.githubusercontent.com/ebics-api/ebics-client-php/3.x/doc/schema"
# Each schema directory of the mirror and the files fetched from it.
_FILES = {
    "H005": (
        "ebics_H005.xsd",
        "ebics_keymgmt_request_H005.xsd",
        "ebics_keymgmt_response_H005.xsd",
        "ebics_orders_H005.xsd",
        "ebics_request_H005.xsd",
        "ebics_response_H005.xsd",
        "ebics_signature_S002.xsd",
        "ebics_types_H005.xsd",
        "xmldsig-core-schema.xsd",
    ),
    "H000": ("ebics_hev.xsd",),
}
_DESTINATION = Path(__file__).resolve().parent.parent / "tests" / "schema"


def main() -> None:
    """Download every schema file into its directory under the destination.

    Uses ``curl`` (which respects the system trust store) rather than urllib, whose
    framework-Python build on macOS often cannot verify TLS certificates.
    """
    for directory, names in _FILES.items():
        destination = _DESTINATION / directory
        destination.mkdir(parents=True, exist_ok=True)
        for name in names:
            url = f"{_MIRROR}/{directory}/{name}"
            subprocess.run(["curl", "-sSf", "-o", str(destination / name), url], check=True)
            print(f"fetched {directory}/{name}")
    print(f"Schemas written to {_DESTINATION}")


if __name__ == "__main__":
    main()
