"""Things worth telling the caller about, as objects rather than as text.

A program cannot act on a formatted string without parsing it back, so each of
these is a small immutable record: fields to read, compare and store. They are
also written to the ``netflume`` logger, so that a caller who wants no more
than a log line gets one for free, but the log line is the courtesy and the
object is the interface.
"""

from collections import namedtuple

__all__ = ["ExportGap", "SamplingChange", "TemplateLearned", "DecodeError"]


class ExportGap(namedtuple("ExportGap",
                           "exporter domain version missed unit")):
    """Exports that never arrived, deduced from a jump in the sequence number.

    exporter  source address of the exporting device
    domain    observation domain, since one exporter can run several
    version   5, 9 or 10
    missed    how many exports the counter skipped
    unit      what those exports are counted in: "export messages",
              "data records" or "flow records". Never add two gaps with
              different units together; the result would mean nothing.

    A gap means loss between the exporter and here, whether a saturated link
    or a receive buffer that filled while this process was busy. It is never a
    decoding failure.
    """

    __slots__ = ()

    def __str__(self):
        return (f"{self.exporter} (v{self.version} domain {self.domain}) "
                f"skipped {self.missed} {self.unit}: exports are being lost "
                f"before they reach the decoder")


class SamplingChange(namedtuple("SamplingChange",
                                "exporter domain rate previous")):
    """A domain has stated, or restated, how much of the traffic it reports.

    exporter  source address of the exporting device
    domain    observation domain, since one exporter can sample each of its
              domains differently
    rate      N, meaning 1 flow in N is exported, so byte and packet counts
              are roughly 1/N of the real figures. 1 means unsampled.
    previous  the rate believed before this, or None if none was known.

    Only changes are reported. An exporter that keeps repeating the same rate,
    which is what they do in every options record, produces one of these the
    first time and nothing after.
    """

    __slots__ = ()

    def __str__(self):
        if self.rate == 1:
            return (f"{self.exporter} (domain {self.domain}) now reports no "
                    f"sampling; counts are complete again")
        return (f"{self.exporter} (domain {self.domain}) reports 1-in-"
                f"{self.rate} sampling; byte and packet counts are a sample, "
                f"so real traffic is roughly {self.rate}x higher")


class TemplateLearned(namedtuple(
        "TemplateLearned",
        "exporter domain template_id fields options previous was_options")):
    """A template this store had not seen before, or one that has changed.

    exporter     source address of the exporting device
    domain       observation domain, since one exporter can run several and
                 allocates template IDs separately in each
    template_id  the ID the exporter gave it, which is only unique within
                 that exporter and domain
    fields       the layout, as a list of (name, kind, length) triples in
                 record order. length 0xFFFF is IPFIX variable length, which
                 means the record itself declares the width.
    options      True for an options template, which describes the exporter
                 rather than traffic. Both kinds are allocated from one pool
                 of IDs, so which kind a template is has to travel with it.
    previous     the layout believed before this, or None when the template
                 is new. A template that changes under an ID already in use
                 is the case worth acting on: every record decoded for that
                 ID afterwards means something different from the ones
                 before it.
    was_options  the kind believed before this, or None when the template is
                 new. It is a field of its own rather than part of
                 `previous`, which named the layout in 0.3.0 and goes on
                 naming it. `options` and `fields` describe the template that
                 has just arrived; `was_options` and `previous` describe the
                 one it replaced, and the pairing is what lets a reader tell
                 a layout that changed from a kind that did.

    Only new and changed templates are reported, exactly as only sampling
    changes are. Exporters resend every template they hold every few minutes,
    which is what keeps a collector that started late able to decode anything,
    and an event per resend would be an event per datagram from the exporters
    that prepend their templates to everything. A caller that wants to see
    every resend is asking a question the store cannot answer from its own
    state, since a resend is by definition indistinguishable from what is
    already held.

    A template evicted under MAX_TEMPLATES and then resent is new again, which
    is truthful rather than a wrinkle: this store no longer knew the layout,
    and the data sets in between were counted in ``stats["deferred"]``.
    """

    __slots__ = ()

    def __str__(self):
        kind = "options template" if self.options else "template"
        where = f"{self.exporter} (domain {self.domain})"
        count = len(self.fields)
        plural = "" if count == 1 else "s"
        if self.previous is None:
            return f"{where} learned {kind} {self.template_id}, {count} field{plural}"
        # A kind that has flipped is said instead of the field count, and is
        # the more consequential of the two: the records stop arriving in one
        # of the decoder's two outputs and start arriving in the other, which
        # a caller reading only flows sees as the template going silent.
        if self.was_options is not None and self.was_options != self.options:
            became = "an options template" if self.options else "a data template"
            now, before = (("option", "flow") if self.options
                           else ("flow", "option"))
            return (f"{where} redefined template {self.template_id} as "
                    f"{became}, {count} field{plural}; its records are now "
                    f"{now} records rather than {before} records")
        return (f"{where} redefined {kind} {self.template_id}: {count} "
                f"field{plural}, was {len(self.previous)}; records decoded "
                f"for it from here on describe a different layout")


class DecodeError(namedtuple("DecodeError", "exporter reason detail")):
    """A datagram that could not be turned into records.

    reason is one of:

    "short"        fewer than two bytes, or too short to hold a header
    "unsupported"  a version this package does not decode (sFlow, say)
    "malformed"    the header parsed but the body did not

    detail is a human-readable string, usually the exception's message. The
    datagram is discarded and collection continues; a decoder that dies on one
    bad packet is useless on a real network.
    """

    __slots__ = ()

    def __str__(self):
        return f"{self.exporter}: {self.reason} datagram discarded ({self.detail})"
