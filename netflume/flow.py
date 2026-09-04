"""A typed view over a decoded flow record.

The parser produces a plain dict and keeps producing one: it is lossless, it
costs nothing when an exporter sends a field nobody anticipated, and a schema
in the parse path would have to grow every time one does. :class:`Flow` sits on
top of that dict rather than replacing it, and is opt-in, because a forwarder
that wants three fields for an MQTT topic should not pay to materialise thirty.

What the type is actually for is not the annotations. It is the four
normalisations below. Each is otherwise open-coded at every call site, and each
is a place where an exporter's choice of encoding quietly changes the answer:

* **octets / octets_total.** IE 1 and IE 85 are different keys for the same
  idea and exporters send one or the other. Read ``rec["octets"]`` alone and
  every IE 85 exporter silently contributes zero bytes: a wrong number rather
  than a missing one, which is the harder kind to notice. Same for packets,
  IE 2 and IE 86.
* **post-NAT addresses.** An exporter may report only the translated addresses.
  :func:`~netflume.parse.flow_endpoints` is the one place that decides where a
  flow's ends are, so that display, filtering and accounting cannot each reach
  a different conclusion about the same flow.
* **timestamps need the header.** Absolute IPFIX times come from the record,
  but v5 and v9 report the start as milliseconds since the exporter booted and
  have to be reconstructed from the header's uptime and export time. So a Flow
  is built from a record *and* its header, never from a record alone.
* **absent is not zero.** Every modelled field except the identifying metadata
  is Optional and stays None when the exporter did not send it. A flow with no
  byte count is not a flow that carried nothing, and a flow with no duration
  says nothing about how long it took.

One class covers all three versions. The wire formats differ; the normalised
record deliberately does not.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from .parse import flow_duration, flow_endpoints, flow_timestamp
from .values import addr_kind, proto_name, service_name, tcp_flags_str

__all__ = ["Flow", "MODELLED_FIELDS", "METADATA_KEYS"]


#: The modelled fields, in a stable order. This is the column set a database
#: table would be built from; it will gain fields in future versions but will
#: not lose or rename them.
MODELLED_FIELDS = (
    "exporter", "version", "domain", "start", "duration",
    "src_addr", "dst_addr", "src_port", "dst_port", "proto",
    "octets", "packets", "tcp_flags", "in_if", "out_if", "sampling_rate",
)

#: The keys :meth:`Flow.as_dict` adds alongside the record's own. Underscored
#: so they cannot collide with an information element name, present or future.
METADATA_KEYS = ("_exporter", "_version", "_timestamp", "_domain",
                 "_duration", "_sampling_rate")

_JSON_SAFE = (str, int, float, bool, type(None))


@dataclass(frozen=True)
class Flow:
    """One decoded flow, with its aliases resolved and its dict still attached.

    Build one with :meth:`from_record`; the constructor takes everything
    already normalised and does no work, which keeps it cheap to copy and
    trivial to fake in a test.

    ``raw`` is the parser's dict and is never copied. Treat it as read-only:
    the Flow is frozen but the dict behind it is not, and mutating it would
    make the typed fields lie.
    """

    raw: Mapping[str, Any] = field(repr=False)

    # == identity, always known =============================================
    exporter: str
    version: int
    domain: int | None
    #: Flow start as unix epoch seconds. Best effort and never None: with
    #: nothing better to go on this is the message's export time. See
    #: :func:`~netflume.parse.flow_timestamp`.
    start: float

    # == everything the exporter may simply not have sent ====================
    src_addr: str | None = None
    dst_addr: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    proto: int | None = None
    octets: int | None = None
    packets: int | None = None
    tcp_flags: int | None = None
    in_if: int | None = None
    out_if: int | None = None
    #: Seconds, or None when the exporter sent no usable start/end pair. None
    #: does not mean instantaneous; exclude such flows from rate arithmetic
    #: rather than dividing by zero or by a guess.
    duration: float | None = None
    #: 1-in-N as last advertised by this exporter, or 1 when it has said
    #: nothing. The counts above are a sample of this size.
    sampling_rate: int = 1

    # == construction ========================================================

    @classmethod
    def from_record(cls, rec, hdr, sampling_rate=1, now=None):
        """Build a Flow from one parser record and the header it arrived under.

        `hdr` is not optional and not decorative: without it a v5 or v9 flow
        has no absolute start time. `sampling_rate` is what the exporter last
        advertised, which the decoder tracks; pass 1 if you are not tracking it.
        `now` overrides the current time for the uptime-wrap guard, for tests.
        """
        src, dst = flow_endpoints(rec)
        return cls(
            raw=rec,
            exporter=hdr.get("exporter"),
            version=hdr.get("version"),
            domain=hdr.get("domain"),
            start=flow_timestamp(rec, hdr, now=now),
            src_addr=src,
            dst_addr=dst,
            src_port=rec.get("src_port"),
            dst_port=rec.get("dst_port"),
            proto=rec.get("proto"),
            # IE 1 or IE 85; exporters send one or the other, never both.
            octets=_first(rec, "octets", "octets_total"),
            packets=_first(rec, "packets", "packets_total"),
            tcp_flags=rec.get("tcp_flags"),
            in_if=rec.get("in_if"),
            out_if=rec.get("out_if"),
            duration=flow_duration(rec),
            sampling_rate=sampling_rate,
        )

    # == the unmodelled remainder ===========================================

    def get(self, key, default=None):
        """Read any field of the underlying record, modelled or not.

        This is how a vendor element reaches a consumer. Unknown standard
        elements are named ``ie<id>`` and enterprise-specific ones
        ``e<enterprise>.<id>``; nothing the exporter sent is dropped on the way
        to here.
        """
        return self.raw.get(key, default)

    def __contains__(self, key):
        return key in self.raw

    # == derived, none of it expensive ======================================

    @property
    def endpoints(self):
        """(source, destination) as a pair, either of which may be None."""
        return (self.src_addr, self.dst_addr)

    @property
    def end(self):
        """Flow end as unix epoch seconds, or None if the duration is unknown."""
        return None if self.duration is None else self.start + self.duration

    @property
    def src_kind(self):
        """"private", "public", "multicast", "special" or "unknown"."""
        return addr_kind(self.src_addr) if self.src_addr else "unknown"

    @property
    def dst_kind(self):
        return addr_kind(self.dst_addr) if self.dst_addr else "unknown"

    @property
    def is_external(self):
        """True when one end is on this network and the other is not.

        Both ends private is local traffic; both public is a flow that only
        transits. This is the "does it touch the internet" question.
        """
        kinds = {self.src_kind, self.dst_kind}
        return "private" in kinds and "public" in kinds

    @property
    def proto_name(self):
        """"TCP", "UDP", or None for a protocol number with no name here."""
        return proto_name(self.proto)

    @property
    def service(self):
        """The well known name for the destination port, or None.

        Reads the destination only. The source port of a client connection is
        ephemeral and naming it produces nonsense.
        """
        return service_name(self.dst_port, self.proto)

    @property
    def flags(self):
        """TCP flags as "CEUAPRSF" with dots for absent ones, "" if unsent."""
        return tcp_flags_str(self.tcp_flags)

    def started_at(self):
        """:attr:`start` as a timezone-aware UTC datetime."""
        return datetime.fromtimestamp(self.start, UTC)

    def scaled(self, value):
        """`value` corrected for the exporter's sampling rate, or None.

        A 1-in-1000 exporter reports a thousandth of the traffic, so its counts
        have to be multiplied back up before they mean anything. None in, None
        out: a missing count scaled by anything is still missing.
        """
        return None if value is None else value * self.sampling_rate

    # == getting out to plain data ==========================================

    def as_dict(self, include_raw=True):
        """A flat, JSON-safe dict with stable keys.

        With `include_raw` (the default) every field the exporter sent is
        present under its normalised name, plus the :data:`METADATA_KEYS`.
        Suited to a document store or a JSONL stream, where an exporter sending
        a new field should widen the record rather than be dropped.

        With ``include_raw=False`` only :data:`MODELLED_FIELDS` appear, under
        their own names: a fixed column set for a database row, with no
        surprise keys when a new exporter appears on the network.

        Timestamps leave as unix epoch floats, deliberately: they are what
        every database and every message payload can store without a
        serialiser, and :meth:`started_at` is one call away for anyone who
        wants a datetime. Values are coerced to str only if they are somehow
        not already JSON-native, which the parser's output always is.
        """
        if not include_raw:
            return {name: _jsonable(getattr(self, name))
                    for name in MODELLED_FIELDS}
        out = {key: _jsonable(value) for key, value in self.raw.items()}
        out["_exporter"] = self.exporter
        out["_version"] = self.version
        out["_timestamp"] = self.start
        out["_domain"] = self.domain
        out["_duration"] = self.duration
        out["_sampling_rate"] = self.sampling_rate
        return out

    def __str__(self):
        src = f"{self.src_addr}:{self.src_port}" if self.src_port else self.src_addr
        dst = f"{self.dst_addr}:{self.dst_port}" if self.dst_port else self.dst_addr
        return (f"{self.proto_name or self.proto} {src} -> {dst} "
                f"{self.octets} bytes")


def _first(rec, *keys):
    """The first of these keys the record actually has, or None."""
    for key in keys:
        value = rec.get(key)
        if value is not None:
            return value
    return None


def _jsonable(value):
    return value if isinstance(value, _JSON_SAFE) else str(value)
