"""Tests for the error hierarchy and its retryability classification."""

from ebicsclient.errors import (
    EbicsError,
    KeyringDecryptionError,
    KeyringFormatError,
    Retryability,
)


def test_errors_default_to_permanent() -> None:
    assert EbicsError().retryability is Retryability.PERMANENT
    assert KeyringFormatError().retryability is Retryability.PERMANENT


def test_wrong_passphrase_is_correctable_not_auto_retryable() -> None:
    assert KeyringDecryptionError().retryability is Retryability.CORRECTABLE


def test_retryability_is_available_when_catching_the_base() -> None:
    try:
        raise KeyringDecryptionError("nope")
    except EbicsError as error:
        assert error.retryability is Retryability.CORRECTABLE


def test_retryability_can_be_set_per_instance_via_the_constructor() -> None:
    assert (
        EbicsError("boom", retryability=Retryability.TRANSIENT).retryability
        is Retryability.TRANSIENT
    )
    # Omitting it falls back to the class default.
    assert EbicsError("boom").retryability is Retryability.PERMANENT
