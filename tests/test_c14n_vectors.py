"""Golden vectors for the EBICS canonicalisation (inclusive Canonical XML 1.0).

Canonicalisation byte-exactness is the AuthSignature's #1 failure point. EBICS mandates
inclusive Canonical XML 1.0 (``http://www.w3.org/TR/2001/REC-xml-c14n-20010315``), which
renders every in-scope namespace on the canonical apex — the opposite of exclusive c14n.
These vectors lock ``crypto.canonicalize`` against output derived by hand from the
Canonical XML 1.0 serialisation rules (not from our own implementation — that would be
circular). A mismatch means our output disagrees with the specification.

The regression guard ``test_no_spurious_empty_namespace_on_descendants`` pins the lxml
subtree bug (spurious ``xmlns=""``) that our standalone-node canonicalisation works around;
the EBICS-shaped cross-check lives in test_php_parity.py.
"""

from lxml import etree

from ebicsclient import crypto


def _canonicalize_root(source: bytes) -> bytes:
    return crypto.canonicalize(etree.fromstring(source))


def _canonicalize_first_child(source: bytes) -> bytes:
    return crypto.canonicalize(etree.fromstring(source)[0])


def test_inherited_namespace_is_kept() -> None:
    # Inclusive c14n renders an in-scope (inherited) namespace on the apex, even unused.
    source = b'<a xmlns:unused="urn:x"><child>text</child></a>'
    assert _canonicalize_first_child(source) == b'<child xmlns:unused="urn:x">text</child>'


def test_no_spurious_empty_namespace_on_descendants() -> None:
    # Regression guard for the lxml subtree bug: descendants sharing the apex's default
    # namespace must NOT get xmlns="".
    source = b'<r xmlns="urn:u"><a><b>x</b></a></r>'
    assert _canonicalize_first_child(source) == b'<a xmlns="urn:u"><b>x</b></a>'


def test_used_prefix_is_rendered() -> None:
    source = b'<a xmlns:p="urn:p"><p:child>x</p:child></a>'
    assert _canonicalize_first_child(source) == b'<p:child xmlns:p="urn:p">x</p:child>'


def test_default_namespace_is_rendered() -> None:
    source = b'<a xmlns="urn:d"><child>x</child></a>'
    assert _canonicalize_first_child(source) == b'<child xmlns="urn:d">x</child>'


def test_namespace_declared_once_not_repeated_on_descendants() -> None:
    source = b'<p:a xmlns:p="urn:p"><p:b>x</p:b></p:a>'
    assert _canonicalize_root(source) == b'<p:a xmlns:p="urn:p"><p:b>x</p:b></p:a>'


def test_attributes_are_ordered_and_empty_elements_expanded() -> None:
    source = b'<el z="1" a="2"/>'
    assert _canonicalize_root(source) == b'<el a="2" z="1"></el>'


def test_text_special_characters_are_escaped() -> None:
    source = b"<a>1 &lt; 2 &amp; 3 &gt; 0</a>"
    assert _canonicalize_root(source) == b"<a>1 &lt; 2 &amp; 3 &gt; 0</a>"
