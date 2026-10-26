"""Read which ISO 20022 message a delivered XML document declares.

Every ISO 20022 message schema sets its ``targetNamespace`` to
``urn:iso:std:iso:20022:tech:xsd:`` followed by the message identifier — business area,
message number, variant and version, as in ``camt.053.001.08`` — so a document's root
namespace names the exact message and version it is. The ZKB documents confirm the form
for camt.052/053/054 (versions 04 and 08) and pain.002 (version 10).
"""

import io
import re
from dataclasses import dataclass

from lxml import etree

from ebicsclient.errors import MessageFormatError

_NAMESPACE_PREFIX = "urn:iso:std:iso:20022:tech:xsd:"
_IDENTIFIER = re.compile(
    r"(?P<message_name>[a-z]{4}\.\d{3})\.(?P<variant>\d{3})\.(?P<version>\d{2})"
)


@dataclass(frozen=True, slots=True)
class MessageIdentifier:
    """An ISO 20022 message identifier, e.g. ``camt.053.001.08``.

    Attributes:
        message_name: Business area and message number, e.g. ``"camt.053"`` — the form
            the BTF ``MsgName`` uses.
        variant: The variant, e.g. ``"001"``.
        version: The version, e.g. ``"08"`` — the form the BTF ``version`` attribute uses.
    """

    message_name: str
    variant: str
    version: str

    def __str__(self) -> str:
        return f"{self.message_name}.{self.variant}.{self.version}"


def root_namespace(document: bytes) -> str | None:
    """Return the namespace of a document's root element, reading only its start tag.

    Args:
        document: The raw XML document bytes.

    Returns:
        The root element's namespace URI, or ``None`` if it declares none.

    Raises:
        MessageFormatError: the document is not readable XML.
    """
    # Hardened parser: no entity expansion, no network access (see docs/06).
    events = etree.iterparse(
        io.BytesIO(document),
        events=("start",),
        resolve_entities=False,
        no_network=True,
        huge_tree=False,
    )
    try:
        _, root = next(events)
    except (etree.XMLSyntaxError, StopIteration) as error:
        raise MessageFormatError(f"Delivered document is not readable XML: {error}") from error
    return etree.QName(root).namespace


def message_identifier(namespace: str | None) -> MessageIdentifier | None:
    """Return the ISO 20022 message a root namespace names.

    Args:
        namespace: A root namespace, as :func:`root_namespace` returns it.

    Returns:
        The message identifier, or ``None`` if the namespace is not an ISO 20022 message
        namespace.
    """
    if namespace is None or not namespace.startswith(_NAMESPACE_PREFIX):
        return None
    match = _IDENTIFIER.fullmatch(namespace.removeprefix(_NAMESPACE_PREFIX))
    if match is None:
        return None
    return MessageIdentifier(
        message_name=match["message_name"],
        variant=match["variant"],
        version=match["version"],
    )
