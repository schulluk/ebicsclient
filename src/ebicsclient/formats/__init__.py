"""Business-message parsers, decoupled from the EBICS transport and protocol version.

Each module here turns the raw order data a download yields into normalised models
(:class:`~ebicsclient.models.Statement`, :class:`~ebicsclient.models.Balance`,
:class:`~ebicsclient.models.Entry`). The library parses ``camt.053.001.08`` today; new
ISO 20022 vintages and message types are added beside :mod:`ebicsclient.formats.camt053`
without touching the transport or protocol layers.
"""
