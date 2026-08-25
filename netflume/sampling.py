"""Reading the sampling rate an exporter advertises.

An exporter that samples reports one flow in N, and the byte and packet counts
it sends are correspondingly short. Nothing downstream can correct for that
without knowing N, so the rate is worth surfacing loudly rather than leaving
the numbers quietly wrong.
"""

import logging
from collections import OrderedDict

from .events import SamplingChange

__all__ = ["MAX_SAMPLING_STREAMS", "SamplingWatch", "sampling_rate"]

#: Sampling states kept before the least recently seen is dropped. Keyed by a
#: forgeable source address, so it needs a ceiling like every other per-exporter
#: table here.
MAX_SAMPLING_STREAMS = 10000

log = logging.getLogger(__name__)


def sampling_rate(rec):
    """Read a 1-in-N sampling rate out of an option data record.

    Returns None when the record says nothing about sampling, as most option
    records describe something else entirely such as interface names, and 1
    when it explicitly describes an unsampled exporter. Those two are different
    answers: the first is silence, the second is news, and a caller holding a
    stale rate needs to be able to tell them apart.

    Exporters advertise sampling in several ways depending on vintage. The v5
    header and the older v9 elements give the interval directly, while IPFIX
    describes the selection process instead: either take `interval` packets and
    skip `space` of them, or take `size` out of every `population`.
    """
    for key in ("sampling_interval", "sampler_interval"):
        value = rec.get(key)
        if value:            # absent, or zero padding, carries no statement
            return max(1, int(value))

    interval = rec.get("sampling_packet_interval")
    space = rec.get("sampling_packet_space")
    # A space of zero means nothing is skipped, so the exporter is unsampled.
    # A space that is missing altogether is silence, not a claim of that.
    if interval and space is not None:
        return max(1, int(round((interval + space) / interval)))

    size = rec.get("sampling_size")
    population = rec.get("sampling_population")
    if size and population and population >= size:
        return max(1, int(round(population / size)))

    return None


class SamplingWatch:
    """Remembers the sampling rate each observation domain advertises.

    Keyed by (exporter, domain), for the same reason
    :class:`~netflume.sequence.SequenceWatch` is: one chassis can run several
    observation domains and sample them differently. Keyed by exporter alone,
    an unsampled second domain deletes the first domain's rate and every flow
    from it silently under-reports its traffic by that factor.

    :meth:`rate_for` is the question a consumer actually has, namely what do I
    have to multiply these counts by, and it can be asked at any time.
    :meth:`take_events` reports the moments the answer changed.
    """

    def __init__(self, max_streams=MAX_SAMPLING_STREAMS):
        self.rates = OrderedDict()
        self.evicted = 0
        self.max_streams = max_streams
        self._events = []

    def note(self, exporter, domain, rec):
        """Fold in one option data record.

        Returns a :class:`~netflume.events.SamplingChange` when this
        record changed what is known about the exporter, otherwise None. The
        same event is queued for :meth:`take_events` and written to the log at
        WARNING (sampling on) or INFO (sampling off).
        """
        rate = sampling_rate(rec)
        if rate is None:
            # This record is about something other than sampling. It is not a
            # statement that sampling is off, so nothing already known changes.
            return None

        key = (exporter, domain)
        if rate == 1:
            # This domain says it is sampling everything. Anything remembered
            # for it is now stale and would misreport the counts. Other domains
            # on the same exporter are untouched: they are separate statements.
            previous = self.rates.pop(key, None)
            if previous:
                event = SamplingChange(exporter, domain, 1, previous)
                self._events.append(event)
                log.info("%s", event)
                return event
            return None

        previous = self.rates.get(key)
        if previous == rate:
            self.rates.move_to_end(key)
            return None
        self.rates[key] = rate
        self.rates.move_to_end(key)
        while len(self.rates) > self.max_streams:
            self.rates.popitem(last=False)
            self.evicted += 1
        event = SamplingChange(exporter, domain, rate, previous)
        self._events.append(event)
        log.warning("%s", event)
        return event

    def rate_for(self, exporter, domain=None):
        """The 1-in-N rate last advertised, or 1 if unsampled.

        Never None: a domain that has said nothing is assumed to be sending
        everything, which is both the common case and the safe reading, since
        the alternative is inventing a multiplier out of nothing.

        `domain` names the observation domain, which is what the rate is
        actually scoped to. Omitting it asks about the exporter as a whole and
        answers only when that is unambiguous: every domain heard from agrees,
        or only one has spoken. When they disagree there is no single right
        answer, so it returns 1 rather than picking one domain's rate and
        applying it to another's counts.
        """
        if domain is not None:
            return self.rates.get((exporter, domain), 1)
        known = {rate for (exp, _domain), rate in self.rates.items()
                 if exp == exporter}
        return known.pop() if len(known) == 1 else 1

    def take_events(self):
        """Hand over the changes seen since the last call, and forget them."""
        events, self._events = self._events, []
        return events
