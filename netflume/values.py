"""Classifying and naming single field values.

What is here is what a consumer of flows genuinely needs and would otherwise
re-derive badly, with the results cached because these questions get asked once
per flow and the answers never change. Formatting helpers for byte sizes, bit
rates and durations rendered for a column are deliberately absent; they are
presentation, and presentation belongs to whatever is doing the presenting.
"""

import ipaddress
import socket
from typing import Dict, Optional, Tuple

from .ie import FLOW_END_REASON, PROTO_NAMES, TCP_FLAG_BITS

__all__ = ["addr_kind", "flow_end_reason_name", "proto_name", "service_name",
           "tcp_flags_str"]


#: Ceiling on the service-name cache, as for _addr_kind_cache below. The key
#: includes the protocol number, which comes off the wire and can be any width
#: the template declares, so a broken or hostile exporter can otherwise grow
#: this without bound in any consumer that touches Flow.service.
MAX_SERVICE_CACHE = 100000

_service_cache: Dict[Tuple[Optional[int], Optional[int]], Optional[str]] = {}


def service_name(port, proto):
    """Look up a well known service name for a port. Cached, best effort.

    Returns None for an ephemeral port (49152 and up), for port 0, and for any
    protocol other than TCP or UDP, since naming those would be a guess.

    This reads the system services database, which on a first miss can touch
    the filesystem, so results are remembered: /etc/services does not change
    under a running process, and the answer for a (port, protocol) pair is the
    same every time.

    The cache is bounded by MAX_SERVICE_CACHE. Past that, lookups still return
    the right answer but stop being remembered, so the cost reverts to one
    database read per call for pairs that were never cached. The ceiling is
    there because the protocol number comes off the wire and can be any width
    a template declares, which makes the key space something an exporter
    controls rather than something bounded by the port range.
    """
    if port is None or port == 0 or port >= 49152:
        return None
    key = (port, proto)
    if key in _service_cache:
        return _service_cache[key]
    name = None
    proto_str = {6: "tcp", 17: "udp"}.get(proto)
    if proto_str:
        try:
            name = socket.getservbyport(port, proto_str)
        except OSError:
            name = None
    if len(_service_cache) < MAX_SERVICE_CACHE:
        _service_cache[key] = name
    return name


_addr_kind_cache: Dict[str, str] = {}
ADDR_KINDS = ("private", "public", "multicast", "special", "unknown")


def addr_kind(addr):
    """Classify an address string as one of :data:`ADDR_KINDS`.

    "private" is RFC 1918 and its IPv6 equivalents, "special" covers loopback,
    link-local, reserved and unspecified, and "unknown" means it did not parse
    as an address at all. Works for both families, since v4 and v6 addresses
    arrive under the same record keys.

    Cached, with a cap: an address seen once is cheap to classify again, and a
    collector watching a busy link must not grow a dictionary without bound.
    """
    if addr in _addr_kind_cache:
        return _addr_kind_cache[addr]
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        kind = "unknown"
    else:
        if ip.is_multicast:
            kind = "multicast"
        elif ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_unspecified:
            kind = "special"
        elif ip.is_private:
            kind = "private"
        else:
            kind = "public"
    if len(_addr_kind_cache) < 100000:
        _addr_kind_cache[addr] = kind
    return kind


def proto_name(proto):
    """"TCP", "UDP" and so on, or None for a protocol number with no name here."""
    return PROTO_NAMES.get(proto)


def flow_end_reason_name(reason):
    """Why the exporter stopped counting: "idle", "active", "eof" and friends."""
    return FLOW_END_REASON.get(reason)


def tcp_flags_str(flags):
    """The flags seen over a flow's lifetime as "CEUAPRSF", dots for absent.

    A TCP flow that opened and closed cleanly reads ".A..RSF" or similar; the
    string is fixed width so it sorts and compares sensibly. Returns "" when
    the exporter sent no flags at all, which is not the same as sending zero.
    """
    if flags is None:
        return ""
    return "".join(ch if flags & bit else "." for bit, ch in TCP_FLAG_BITS)
