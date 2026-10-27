"""Tests for ebicsclient.experimental: what it holds, and that it stays apart.

An experimental item is not bank-tested end to end, but whatever can be checked offline is
checked here: a BTF constant must still match the bank's HTD registry.
"""

from pathlib import Path

import ebicsclient
from ebicsclient import experimental
from ebicsclient.protocol import h005


def test_sepa_constant_is_registered_at_the_bank() -> None:
    order_data = (Path(__file__).parent / "data" / "htd_zkb_sample.xml").read_bytes()
    permitted = {
        entry.service
        for entry in h005.parse_subscriber_info(order_data).permissions
        if entry.service is not None
    }
    assert experimental.PAIN_001_SEPA in permitted


def test_experimental_items_are_not_exported_from_the_regular_api() -> None:
    # Moving an item to the regular API is a deliberate step after a live test, never a
    # side effect of an import.
    for name in experimental.__all__:
        assert name not in ebicsclient.__all__
        assert not hasattr(ebicsclient, name)
