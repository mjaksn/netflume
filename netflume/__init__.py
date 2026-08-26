"""NetFlow v5, NetFlow v9 and IPFIX collection and parsing, as a library.

Built for programs rather than for terminals: a daemon writing flows to a
database, a process forwarding a subset of fields over MQTT, an analyser
replaying a capture. Standard library only, so it installs anywhere Python
does and adds nothing to a deployment's dependency surface.

Two layers, and either can be used without the other:

**Parsing.** :func:`~netflume.parse.parse_message` and friends turn
bytes into records. No socket, no clock the caller cannot control, no state
beyond the :class:`~netflume.parse.TemplateStore` you hand in. Feed it
from a pcap, a queue or a test fixture.

**Collection.** :class:`Collector` binds a UDP socket and yields what arrives::

    from netflume import Collector

    with Collector(port=2055) as collector:
        for flow in collector.flows():
            print(flow.src_addr, flow.dst_addr, flow.octets)

A flow is a plain dict of normalised keys, the same keys whichever version the
exporter speaks, and :class:`~netflume.flow.Flow` is an opt-in typed view over
that dict which resolves the field aliases and keeps the dict attached. The
README documents both shapes.

Nothing here prints. Sampling rates, export gaps and undecodable datagrams are
:mod:`~netflume.events` objects from
:meth:`~netflume.decoder.Decoder.take_events`, and are also written to
the ``netflume`` logger for callers who want no more than that. As a
library should, this package adds nothing but a NullHandler; configure a real
handler, or records go nowhere.

Hostname resolution is not here. It was an optional module that nothing else
in this package imported, and it now lives on its own as ``lanname``: reverse
DNS, mDNS and NetBIOS behind a cache, non-blocking, and off until a mode is
chosen. Install it alongside if a consumer wants names. Nothing here needs it.
"""

import logging

from .collector import DEFAULT_PORT, DEFAULT_RCVBUF, Collector
from .decoder import Decoder, Message
from .events import DecodeError, ExportGap, SamplingChange
from .flow import METADATA_KEYS, MODELLED_FIELDS, Flow
from .ie import FLOW_END_REASON, IE, PROTO_NAMES, TCP_FLAG_BITS
from .parse import (
                    SUPPORTED_VERSIONS,
                    TemplateStore,
                    flow_duration,
                    flow_endpoints,
                    flow_timestamp,
                    parse_message,
                    parse_v5,
                    parse_v9_or_ipfix,
)
from .sampling import SamplingWatch, sampling_rate
from .sequence import SequenceWatch
from .values import (
                    ADDR_KINDS,
                    addr_kind,
                    flow_end_reason_name,
                    proto_name,
                    service_name,
                    tcp_flags_str,
)

__version__ = "0.1.0"

# A library that logs to an unconfigured root logger prints to stderr, which is
# exactly what this package exists not to do.
logging.getLogger(__name__).addHandler(logging.NullHandler())

__all__ = [
    # collection
    "Collector", "DEFAULT_PORT", "DEFAULT_RCVBUF", "Decoder", "Message",
    # the flow shape
    "Flow", "MODELLED_FIELDS", "METADATA_KEYS",
    # parsing
    "TemplateStore", "parse_message", "parse_v5", "parse_v9_or_ipfix",
    "flow_endpoints", "flow_timestamp", "flow_duration", "SUPPORTED_VERSIONS",
    # what the exporter says about itself
    "SamplingWatch", "sampling_rate", "SequenceWatch",
    # events
    "ExportGap", "SamplingChange", "DecodeError",
    # field level helpers
    "addr_kind", "ADDR_KINDS", "service_name", "proto_name", "tcp_flags_str",
    "flow_end_reason_name", "IE", "PROTO_NAMES", "FLOW_END_REASON",
    "TCP_FLAG_BITS",
    "__version__",
]
