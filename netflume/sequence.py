"""Finding gaps in the sequence numbers exporters stamp on messages.

A jump in the counter means messages went missing on the way here, usually
dropped by the network or by a socket buffer that filled while the receive loop
was busy. Without this the loss is silent: a flow that never arrives looks
exactly like a flow that never happened.
"""

import logging
from collections import Counter, OrderedDict

from .events import ExportGap

__all__ = ["MAX_STREAMS", "SequenceWatch"]

log = logging.getLogger(__name__)

SEQ_MODULUS = 0x100000000        # the counter is 32 bits and wraps
MAX_PLAUSIBLE_GAP = 1000000      # past this the counter restarted, not slipped
MAX_REORDER = 1000               # how far back a late datagram can plausibly be
RESYNC_AFTER = 5                 # backward steps in a row before assuming a restart
MAX_STREAMS = 10000              # tracked streams before the oldest is dropped


class SequenceWatch:
    """Finds gaps in the sequence numbers exporters stamp on export messages.

    What the counter counts depends on the version: v5 counts flow records and
    IPFIX counts data records, while v9 is specified to count export packets
    but is widely implemented as counting records instead. Rather than trust
    the version, each stream is watched until one reading lands exactly on the
    next message, and that reading becomes the rule for that stream. Until one
    does, nothing is reported: the wrong rule would invent a loss on every
    message, and a collector that cries wolf about dropped flows is worse than
    one that stays quiet.

    An exporter sending exactly one record per message is ambiguous forever and
    is watched without ever being judged; :meth:`watched` says whether anything
    has been learned.
    """

    def __init__(self, max_streams=MAX_STREAMS):
        # All three are keyed by stream, not by exporter: one exporter can run
        # several observation domains, and their counters are independent
        # sequence spaces that must not be added together.
        self.streams = OrderedDict()  # (exporter, domain, version) -> state
        self.missed = Counter()  # stream -> exports that never arrived
        self.units = {}          # stream -> what those exports are counted in
        self.resyncs = 0
        self.backwards = 0
        self.evicted = 0
        self.max_streams = max_streams
        # An OrderedDict used as a bounded set. A plain set grows one entry per
        # source address, and those are forgeable.
        self._warned = OrderedDict()
        self._events = []

    def _evict(self):
        """Drop the least recently seen stream, and everything keyed by it."""
        while len(self.streams) > self.max_streams:
            key, _state = self.streams.popitem(last=False)
            self.missed.pop(key, None)
            self.units.pop(key, None)
            self.evicted += 1
        while len(self._warned) > self.max_streams:
            self._warned.popitem(last=False)

    def observe(self, exporter, domain, version, seq, flows, options=0):
        """Fold in one message. Returns how many exports appear to be missing.

        The count is the return value; :meth:`take_events` yields the first gap
        seen for each exporter as an :class:`~netflume.events.ExportGap`
        for callers who want to act on it rather than count it.
        """
        if seq is None:
            return 0

        # IPFIX counts every data record it sends, and option records are data
        # records too, so they count towards the sequence even though they are
        # not flows.
        records = flows + options if version == 10 else flows

        key = (exporter, domain, version)
        state = self.streams.get(key)
        if state is None:
            self.streams[key] = {"seq": seq, "records": records, "mode": None,
                                 "backwards": 0}
            self._evict()
            return 0
        self.streams.move_to_end(key)

        by_messages = (state["seq"] + 1) % SEQ_MODULUS
        by_records = (state["seq"] + state["records"]) % SEQ_MODULUS

        if state["mode"] is None:
            # Learn how this exporter counts. A message carrying a single record
            # advances both readings equally and so teaches nothing.
            if by_messages != by_records:
                if seq == by_messages:
                    state["mode"] = "messages"
                elif seq == by_records:
                    state["mode"] = "records"
            state["seq"], state["records"] = seq, records
            return 0

        expected = by_messages if state["mode"] == "messages" else by_records
        gap = ((seq - expected + SEQ_MODULUS // 2) % SEQ_MODULUS) - SEQ_MODULUS // 2

        if gap < 0:
            if gap >= -MAX_REORDER and state["backwards"] + 1 < RESYNC_AFTER:
                # A repeat or a reordered datagram. The high-water mark stays
                # where it is, or the next message in order would look like a
                # fresh gap.
                state["backwards"] += 1
                self.backwards += 1
                return 0
            # A long step back, or a run of them, is not reordering: the
            # exporter restarted and its counter began again. Adopt the new
            # base, otherwise every later message reads as stale forever.
            self.resyncs += 1
            state.update(seq=seq, records=records, backwards=0)
            return 0

        state["seq"], state["records"], state["backwards"] = seq, records, 0

        if gap == 0:
            return 0
        if gap > MAX_PLAUSIBLE_GAP:
            # A forward jump this large is a restart too, not a loss of that
            # many exports. Carry on from wherever the counter now is.
            self.resyncs += 1
            return 0

        self.missed[key] += gap
        self.units[key] = self._unit(state["mode"], version)
        # Reported per exporter rather than per stream: the running event is a
        # heads-up that something is being lost here, and report() carries the
        # breakdown.
        if exporter not in self._warned:
            self._warned[exporter] = True
            event = ExportGap(exporter, domain, version, gap, self.units[key])
            self._events.append(event)
            log.warning("%s", event)
        return gap

    # == events =============================================================

    def take_events(self):
        """Hand over the events raised since the last call, and forget them.

        Returns a list of :class:`~netflume.events.ExportGap`. Empty is
        the normal answer.
        """
        events, self._events = self._events, []
        return events

    # == summary ============================================================

    def report(self):
        """Summary rows as (label, count, unit), worst first.

        Streams are reported separately, since adding a count of export
        messages to a count of data records would produce a number that means
        nothing. The domain and version are named only when an exporter has
        lost exports on more than one stream, where the bare address would be
        ambiguous.
        """
        streams_per_exporter = Counter(key[0] for key in self.missed)
        rows = []
        for key, count in self.missed.most_common():
            exporter, domain, version = key
            label = exporter
            if streams_per_exporter[exporter] > 1:
                label = f"{exporter} v{version} domain {domain}"
            rows.append((label, count, self.units.get(key, "exports")))
        return rows

    def gaps(self):
        """Every stream that has lost exports, as ExportGap records.

        Unlike :meth:`take_events` this is cumulative and can be read at any
        time, which is what a periodic health check wants.
        """
        return [ExportGap(exporter, domain, version, count,
                          self.units.get((exporter, domain, version), "exports"))
                for (exporter, domain, version), count
                in self.missed.most_common()]

    @staticmethod
    def _unit(mode, version):
        if mode == "messages":
            return "export messages"
        return "flow records" if version == 5 else "data records"

    def watched(self):
        """True once any stream has been read long enough to trust a gap."""
        return any(state["mode"] for state in self.streams.values())
