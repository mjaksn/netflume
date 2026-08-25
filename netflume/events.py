"""Things worth telling the caller about, as objects rather than as text.

A program cannot act on a formatted string without parsing it back, so each of
these is a small immutable record: fields to read, compare and store. They are
also written to the ``netflume`` logger, so that a caller who wants no more
than a log line gets one for free, but the log line is the courtesy and the
object is the interface.
"""

from collections import namedtuple

__all__ = ["ExportGap", "SamplingChange", "DecodeError"]


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
