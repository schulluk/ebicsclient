"""Ask the bank what it offers, before onboarding and after it.

A bank's EBICS access is not the standard, it is a configuration: which EBICS versions the
host speaks, which optional features it supports, and which business transaction formats
it has registered for the customer, with how many signatures an upload needs. A catalogue
or a colleague's notes are a guess; the bank's own answers are the ground truth behind
every ``091005 EBICS_INVALID_ORDER_IDENTIFIER`` and every upload that goes nowhere.

The example asks in the order the answers become available:

1. **HEV** needs no keys and no subscriber, so it works before INI and HIA: does the host
   speak H005 (EBICS 3.0), the only version this library implements?
2. **HPD**, after HPB: the bank's addresses, the key versions it accepts, and whether it
   supports recovery, pre-validation, HKD/HTD and HAA.
3. **HTD**: the order types registered for the customer and this subscriber's permissions,
   each with its BTF, the number of signatures an upload requires and the subscriber's
   own signature class.
4. **HAA**: which of those order types have data waiting right now.

It ends with a practical use of the registry. The pain.002 download is registered without
a container at ZKB (``PAIN_002``) and with the ZIP container at PostFinance
(``PAIN_002_ZIP``), and each bank refuses the other form. Instead of guessing, the example
looks the tuple up in HTD and says which constant to pass to
``download_payment_status_reports()``.

    uv run python examples/08_bank_discovery.py
"""

from ebicsclient import (
    PAIN_002,
    PAIN_002_ZIP,
    BusinessTransactionFormat,
    Client,
    OrderTypeInfo,
    TransportError,
)

from _config import client_from_env, load_environment, online_client

#: The protocol version of EBICS 3.0, the only one this library implements.
EBICS_30_PROTOCOL_VERSION = "H005"


def main() -> int:
    """Print what the bank offers: versions, parameters, registered order types, waiting data."""
    load_environment()

    offline = client_from_env()  # HEV needs no bank keys, so no HPB yet
    if not _check_versions(offline):
        return 1

    client = online_client()
    _print_bank_parameters(client)
    subscriber = client.subscriber_info()
    _print_registry(subscriber.order_types, subscriber.permissions)
    _print_waiting(client)
    _print_pain002_form(subscriber.permissions)
    return 0


def _check_versions(client: Client) -> bool:
    """HEV: list the EBICS versions the host speaks and say whether H005 is among them."""
    try:
        versions = client.supported_versions()
    except TransportError as error:
        print(f"HEV failed: {error} (some banks answer an unknown Host ID with an HTTP error)")
        return False
    listed = ", ".join(f"{version.protocol_version} ({version.release})" for version in versions)
    print(f"HEV: the host speaks {listed if listed else 'no listed version'}")
    if all(version.protocol_version != EBICS_30_PROTOCOL_VERSION for version in versions):
        print("  H005 is not among them; this library implements EBICS 3.0 only.")
        return False
    return True


def _print_bank_parameters(client: Client) -> None:
    """HPD: the bank's addresses, accepted key versions and optional features."""
    parameters = client.bank_parameters()
    host = parameters.host_id if parameters.host_id is not None else "not stated"
    print(f"\nHPD: {parameters.institute} (host {host})")
    for address in parameters.urls:
        valid = f" from {address.valid_from.isoformat()}" if address.valid_from is not None else ""
        print(f"  address {address.url}{valid}")
    print(
        f"  protocol {', '.join(parameters.protocol_versions)}; "
        f"signature {', '.join(parameters.signature_versions)}; "
        f"authentication {', '.join(parameters.authentication_versions)}; "
        f"encryption {', '.join(parameters.encryption_versions)}"
    )
    for feature, supported in (
        ("transaction recovery", parameters.supports_recovery),
        ("pre-validation", parameters.supports_pre_validation),
        ("HKD/HTD customer data", parameters.supports_client_data_download),
        ("HAA list of waiting data", parameters.supports_downloadable_order_data),
    ):
        print(f"  {feature}: {'yes' if supported else 'no'}")


def _print_registry(
    order_types: tuple[OrderTypeInfo, ...], permissions: tuple[OrderTypeInfo, ...]
) -> None:
    """HTD: the customer's registered order types and this subscriber's permissions."""
    print(f"\nHTD: {len(order_types)} order type(s) registered for the customer")
    for info in order_types:
        signatures = ""
        if info.number_of_signatures_required is not None:
            signatures = f"  {info.number_of_signatures_required} signature(s) required"
        description = f"  {info.description}" if info.description is not None else ""
        print(
            f"  {info.admin_order_type:<4} {_describe(info.service):<46}{signatures}{description}"
        )

    print(f"\nHTD: {len(permissions)} permission(s) for this subscriber")
    for info in permissions:
        level = ""
        if info.authorisation_level is not None:
            level = f"  signature class {info.authorisation_level.value}"
        limit = ""
        if info.maximum_amount is not None:
            limit = f"  up to {info.maximum_amount} {info.maximum_amount_currency}"
        print(f"  {info.admin_order_type:<4} {_describe(info.service):<46}{level}{limit}")


def _print_waiting(client: Client) -> None:
    """HAA: the order types with data waiting right now."""
    waiting = client.available_order_types()
    print(f"\nHAA: {len(waiting)} order type(s) with data waiting")
    for btf in waiting:
        print(f"  {_describe(btf)}")


def _print_pain002_form(permissions: tuple[OrderTypeInfo, ...]) -> None:
    """Look the registered form of the pain.002 download up instead of guessing it."""
    registered = _registered_form(permissions, PAIN_002)
    print("\nThe pain.002 download, as this bank registers it:")
    if registered is None:
        print(f"  not registered for this subscriber; {_describe(PAIN_002)} would be refused")
    elif registered == PAIN_002:
        print(f"  {_describe(registered)}: the default of download_payment_status_reports() fits")
    elif registered == PAIN_002_ZIP:
        print(f"  {_describe(registered)}: pass PAIN_002_ZIP to download_payment_status_reports()")
    else:
        print(f"  {_describe(registered)}: pass this tuple to download_payment_status_reports()")


def _registered_form(
    permissions: tuple[OrderTypeInfo, ...], wanted: BusinessTransactionFormat
) -> BusinessTransactionFormat | None:
    """Return the registered BTF with the service, message and version of ``wanted``, if any."""
    for info in permissions:
        service = info.service
        if (
            service is not None
            and service.service_name == wanted.service_name
            and service.message_name == wanted.message_name
            and service.message_version == wanted.message_version
        ):
            return service
    return None


def _describe(btf: BusinessTransactionFormat | None) -> str:
    """Format a BTF as ``service/scope/option/message vNN container=...``; ``-`` for none."""
    if btf is None:
        return "-"
    return (
        f"{btf.service_name}/{btf.scope or '-'}/{btf.service_option or '-'}/{btf.message_name}"
        f" v{btf.message_version or '-'} container={btf.container or '-'}"
    )


if __name__ == "__main__":
    raise SystemExit(main())
