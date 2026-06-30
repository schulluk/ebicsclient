"""EBICS protocol envelopes, separated by H-schema version.

Only H005 (EBICS 3.0) is implemented; the package boundary keeps the version-specific
XML isolated so another version could be added without touching the rest of the library
(see docs/04 extension axes). A version registry/interface is intentionally deferred
until a second version is real.
"""
