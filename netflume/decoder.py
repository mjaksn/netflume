"""Turning datagrams into messages, and remembering what that implies.

:class:`Decoder` is the parsing layer with its state attached: the template
store that has to outlive a datagram, the sequence watch that can only find a
gap by comparing one message with the last, and the sampling watch that has to
remember what an exporter said an hour ago. It has no socket in it, so a caller
holding bytes from a pcap, a queue or a test fixture gets the same answers a
live collector would.
"""

import logging
import struct
from collections import Counter, deque
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from .events import DecodeError
from .flow import Flow
from .parse import SUPPORTED_VERSIONS, TemplateStore, parse_v5, parse_v9_or_ipfix
from .sampling import SamplingWatch
from .sequence import SequenceWatch

__all__ = ["Decoder", "MAX_PENDING_EVENTS", "Message"]

log = logging.getLogger(__name__)

#: Events held for :meth:`Decoder.take_events` before the oldest are dropped.
#: A collector on an open UDP port receives things that are not NetFlow, such
#: as scanners, sFlow on the same port, or a misconfigured exporter, and each
#: one raises a DecodeError. A caller that never drains would otherwise
#: accumulate one per bad datagram for as long as the process runs. Drops are
#: counted in ``stats["events_dropped"]`` so that the loss is visible rather
#: than silent.
MAX_PENDING_EVENTS = 10000


@dataclass
class Message:
    """One export datagram, decoded.

    The message is the unit that arrives on the wire, and some things are only
    true of a message rather than of a flow: the sequence number, the export
    time, and whether anything was lost getting here.
    """

    #: The header dict: version, exporter, domain, sequence, unix_secs,
    #: sys_uptime. Needed to timestamp a v5 or v9 flow, so keep it with the
    #: records rather than discarding it.
    header: Mapping[str, Any]
    #: Flow records, as plain dicts of normalised keys.
    flows: list[dict[str, Any]] = field(default_factory=list)
    #: Option records: what the exporter says about itself, not about traffic.
    #: Sampling rates are read out of these automatically; interface names and
    #: the like are left for the caller to use or ignore.
    options: list[dict[str, Any]] = field(default_factory=list)
    #: Exports the sequence counter says never arrived before this message. 0
    #: is the normal answer, and is also the answer while the stream is still
    #: being learned. See :class:`~netflume.sequence.SequenceWatch`.
    gap: int = 0
    #: The 1-in-N rate in force for this exporter, 1 if unsampled or unstated.
    sampling_rate: int = 1

    @property
    def exporter(self):
        return self.header.get("exporter")

    @property
    def version(self):
        return self.header.get("version")

    @property
    def sequence(self):
        return self.header.get("sequence")

    def typed_flows(self, now=None):
        """The flow records as :class:`~netflume.flow.Flow` objects.

        Built on demand, not up front: a consumer that wants two fields out of
        a dict should not pay to construct thirty.
        """
        return [Flow.from_record(rec, self.header, self.sampling_rate, now=now)
                for rec in self.flows]

    def __len__(self):
        return len(self.flows)

    def __bool__(self):
        """Always True. A Message exists or it is None; there is no empty one.

        Without this, ``__len__`` makes a message carrying only template sets,
        only option records, or only a sequence gap evaluate false, and the
        natural ``if message:`` after :meth:`~netflume.collector.Collector.poll`
        silently discards all three. Ask ``if message is not None`` to test for
        a decode, and ``len(message)`` or ``message.flows`` for traffic.
        """
        return True


class Decoder:
    """Stateful decoding of one exporter's datagrams, or of many.

    Templates, sequence tracking and sampling rates are all keyed by
    (exporter, observation domain) inside, so one Decoder can serve every device
    sending to a collector, and a device running several domains keeps them
    apart. It is not thread safe; give each thread its own, or put one behind a
    queue.

    The per-exporter tables have ceilings, namely MAX_TEMPLATES, MAX_STREAMS
    and MAX_SAMPLING_STREAMS, because a UDP source address is whatever the
    sender typed, and anything keyed by one and never evicted is a memory leak
    that anyone able to reach the socket can pull on.
    """

    def __init__(self, track_sequence=True, track_sampling=True):
        self.templates = TemplateStore()
        self.stats = Counter()
        self.sequence = SequenceWatch() if track_sequence else None
        self.sampling = SamplingWatch() if track_sampling else None
        self._events = deque()

    def decode(self, data, exporter):
        """Decode one datagram. Returns a :class:`Message`, or None.

        None means nothing usable was in it: too short, a version this package
        does not decode, or a body that would not parse. Every one of those is
        counted in :attr:`stats` and queued as a
        :class:`~netflume.events.DecodeError`; none of them raises,
        because a decoder that dies on one bad packet is useless on a real
        network.

        A Message with no flows in it is not a failure. Template sets, option
        records and data sets whose template has not arrived yet all produce
        one, and an exporter's first few datagrams are routinely all template.
        What those datagrams taught is in :meth:`take_events` as
        :class:`~netflume.events.TemplateLearned`, whether or not this returns
        a Message.
        """
        self.stats["packets"] += 1
        self.stats["bytes_rx"] += len(data)

        if len(data) < 2:
            return self._fail(exporter, "short", "fewer than two bytes")

        version = struct.unpack_from("!H", data, 0)[0]
        if version not in SUPPORTED_VERSIONS:
            self.stats["unsupported_version"] += 1
            return self._fail(exporter, "unsupported",
                              f"version {version}", counted=True)

        try:
            if version == 5:
                hdr, records, opts = parse_v5(data, exporter)
            else:
                hdr, records, opts = parse_v9_or_ipfix(
                    data, exporter, self.templates, self.stats)
        except Exception as exc:      # keep listening even on a bad datagram
            self.stats["parse_errors"] += 1
            # Drained before the failure is reported and not skipped because
            # of it. A template set can parse perfectly and the set behind it
            # be the one that raised, and a layout learned that way is both
            # true and the thing most worth knowing about a datagram that went
            # wrong: every later record for that ID is read through it.
            self._queue(self.templates.take_events())
            return self._fail(exporter, "malformed",
                              f"{type(exc).__name__}: {exc}", counted=True)
        self._queue(self.templates.take_events())

        if hdr is None:
            return self._fail(exporter, "short", "truncated header")

        self.stats[f"v{version}_msgs"] += 1
        self.stats["flows"] += len(records)
        self.stats["option_records"] += len(opts)

        gap = 0
        if self.sequence is not None:
            gap = self.sequence.observe(exporter, hdr.get("domain"), version,
                                        hdr.get("sequence"), len(records),
                                        len(opts))
            if gap:
                self.stats["missed_exports"] += gap
            self._queue(self.sequence.take_events())

        rate = 1
        if self.sampling is not None:
            domain = hdr.get("domain")
            for opt in opts:
                self.sampling.note(exporter, domain, opt)
            self._queue(self.sampling.take_events())
            rate = self.sampling.rate_for(exporter, domain)

        return Message(header=hdr, flows=records, options=opts, gap=gap,
                       sampling_rate=rate)

    def flows(self, data, exporter, typed=False, now=None):
        """Decode a datagram straight to its flows, discarding the rest.

        The convenience form for a caller who has bytes and wants records. The
        header is still needed to timestamp them, so `typed=True` is the shape
        to use if you want start times; the dict form leaves that to you.
        """
        message = self.decode(data, exporter)
        if message is None:
            return []
        return message.typed_flows(now=now) if typed else message.flows

    # == what the caller may want to know ====================================

    def _queue(self, events):
        """Add events to the pending queue, oldest dropped past the ceiling."""
        for event in events:
            if len(self._events) >= MAX_PENDING_EVENTS:
                self._events.popleft()
                self.stats["events_dropped"] += 1
            self._events.append(event)

    def take_events(self):
        """Hand over everything raised since the last call, and forget it.

        A list of :class:`~netflume.events.ExportGap`,
        :class:`~netflume.events.SamplingChange`,
        :class:`~netflume.events.TemplateLearned` and
        :class:`~netflume.events.DecodeError`. Empty is the normal
        answer on a settled network, so this is cheap to call in a loop. It
        is not the answer while one is starting up, since the first datagram
        carrying each of an exporter's templates raises a TemplateLearned.
        """
        events = list(self._events)
        self._events.clear()
        return events

    def sampling_rate(self, exporter, domain=None):
        """The 1-in-N rate last advertised, or 1.

        Rates are scoped to an observation domain, so name one. Omitting it
        answers for the exporter as a whole, and only when its domains agree.
        See :meth:`~netflume.sampling.SamplingWatch.rate_for`.
        """
        return self.sampling.rate_for(exporter, domain) if self.sampling else 1

    def export_gaps(self):
        """Cumulative loss per stream, as ExportGap records, worst first."""
        return self.sequence.gaps() if self.sequence else []

    def _fail(self, exporter, reason, detail, counted=False):
        if not counted:
            self.stats["malformed"] += 1
        error = DecodeError(exporter, reason, detail)
        self._queue((error,))
        log.debug("%s", error)
        return None
