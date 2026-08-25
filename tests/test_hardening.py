"""Wrong answers delivered confidently, and tables that grow without end.

Every case here decodes without raising, which is why none were caught by the
fuzzer: it attacks the promise that ``decode`` never raises, and all of these
keep that promise while returning something untrue. A collector whose whole
claim is that you can tell when an exporter's numbers are trustworthy has to be
held to the numbers, not merely to staying upright.

The bounds tests are the same concern from the other side: the state kept per
exporter is keyed by a source address, and the source address of a UDP datagram
is whatever the sender typed.
"""

import struct
import unittest
from collections import Counter
from unittest import mock

from netflume import Decoder, SamplingWatch, SequenceWatch, values
from netflume.decoder import MAX_PENDING_EVENTS
from netflume.flow import Flow
from netflume.parse import (
    NTP_EPOCH,
    TemplateStore,
    decode_value,
    flow_duration,
    flow_timestamp,
    parse_v9_or_ipfix,
)

from . import packets as p


def spec(eid, length):
    return struct.pack("!HH", eid, length)


def ntp(unix_seconds):
    """A UNIX time as the 64-bit NTP word an exporter would put on the wire."""
    whole = int(unix_seconds)
    frac = int(round((unix_seconds - whole) * (1 << 32)))
    return ((whole + NTP_EPOCH) << 32) | frac


class NtpTimestamps(unittest.TestCase):
    """RFC 7011 6.1.9/6.1.10: IE 154-157 are NTP, not counts since 1970.

    Read as epoch microseconds, a 2025 timestamp lands in the year 540,000,
    every duration comes out 2**32/1e6 = 4295x too long, and Flow.started_at
    raises OSError instead of returning a datetime.
    """

    START = 1755734400.0            # 2025-08-21 00:00:00 UTC
    LENGTH = 12.5

    def decode_one(self, fields, payload, exporter="10.0.0.1"):
        store, stats = TemplateStore(), Counter()
        parse_v9_or_ipfix(p.ipfix([p.template_set([(300, fields)])]),
                          exporter, store, stats)
        hdr, records, _ = parse_v9_or_ipfix(
            p.ipfix([p.data_set(300, payload)], seq=1), exporter, store, stats)
        return hdr, records[0]

    def microsecond_flow(self):
        return self.decode_one(
            [(154, 8), (155, 8), (8, 4), (12, 4)],
            struct.pack("!QQ", ntp(self.START), ntp(self.START + self.LENGTH))
            + b"\xc0\xa8\x01\x0a" + b"\x08\x08\x08\x08")

    def test_a_microsecond_timestamp_is_the_time_it_says(self):
        hdr, rec = self.microsecond_flow()
        self.assertAlmostEqual(flow_timestamp(rec, hdr), self.START, places=3)

    def test_a_microsecond_duration_is_not_4295_times_too_long(self):
        _, rec = self.microsecond_flow()
        self.assertAlmostEqual(flow_duration(rec), self.LENGTH, places=3)

    def test_started_at_returns_a_datetime_rather_than_raising(self):
        hdr, rec = self.microsecond_flow()
        started = Flow.from_record(rec, hdr, 1).started_at()
        self.assertEqual((started.year, started.month), (2025, 8))

    def test_nanosecond_elements_decode_the_same_way(self):
        hdr, rec = self.decode_one(
            [(156, 8), (157, 8)],
            struct.pack("!QQ", ntp(self.START), ntp(self.START + self.LENGTH)))
        self.assertAlmostEqual(flow_timestamp(rec, hdr), self.START, places=3)
        self.assertAlmostEqual(flow_duration(rec), self.LENGTH, places=3)

    def test_the_epoch_count_elements_are_left_alone(self):
        # IE 150-153 really are counts since 1970 and must not be shifted by
        # the NTP epoch as well. This pins the fix's blast radius.
        hdr, rec = self.decode_one(
            [(152, 8), (153, 8)],
            struct.pack("!QQ", int(self.START * 1000),
                        int((self.START + self.LENGTH) * 1000)))
        self.assertAlmostEqual(flow_timestamp(rec, hdr), self.START, places=3)
        self.assertAlmostEqual(flow_duration(rec), self.LENGTH, places=3)

    def test_an_all_zero_timestamp_is_unset_not_the_year_1900(self):
        self.assertEqual(decode_value(b"\x00" * 8, "ntp"), 0)

    def test_a_wrong_length_ntp_field_does_not_reach_the_arithmetic(self):
        # A template may declare IE 154 with any length it likes.
        for raw in (b"\x00\x00\x00\x01", b"", b"\xff" * 16):
            with self.subTest(length=len(raw)):
                self.assertNotIsInstance(decode_value(raw, "ntp"), float)


class TruncatedTemplatesAreNotLearned(unittest.TestCase):
    """A template set ending mid-template must not be stored short.

    Stored short, the next well-formed data set for that ID is cut into one
    real flow plus fabricated ones, and those reach the caller as traffic. The
    bad template survives until the exporter's next refresh, commonly minutes.
    """

    def setUp(self):
        self.store = TemplateStore()
        self.stats = Counter()

    def parse(self, msg, exporter="10.0.0.1"):
        return parse_v9_or_ipfix(msg, exporter, self.store, self.stats)

    def truncated_set(self, tid=301, declared=7, carried=3):
        fields = [(8, 4), (12, 4), (7, 2), (11, 2), (4, 1), (2, 4), (1, 4)]
        body = (struct.pack("!HH", tid, declared)
                + b"".join(spec(e, ln) for e, ln in fields[:carried]))
        return p.raw_set(2, body)

    def test_the_short_template_is_refused(self):
        self.parse(p.ipfix([self.truncated_set()]))
        self.assertEqual(self.store.get("10.0.0.1", 0, 301), (None, False))

    def test_and_so_no_flows_are_fabricated_from_it(self):
        self.parse(p.ipfix([self.truncated_set()]))
        payload = (b"\xc0\xa8\x01\x0a" b"\x08\x08\x08\x08" b"\xd4\x31"
                   b"\x00\x35" b"\x06" + struct.pack("!II", 10, 5000))
        _, records, _ = self.parse(p.ipfix([p.data_set(301, payload)], seq=1))
        # Losing the flow is the right trade: the template will be resent, and
        # a missing flow is recoverable where an invented one is not.
        self.assertEqual(records, [])

    def test_a_truncated_ipfix_options_template_is_refused_too(self):
        body = (struct.pack("!HHH", 302, 4, 1)
                + spec(346, 4) + spec(34, 4))       # declares 4, carries 2
        self.parse(p.ipfix([p.raw_set(3, body)]))
        self.assertEqual(self.store.get("10.0.0.1", 0, 302), (None, False))

    def test_a_template_set_carrying_several_still_works(self):
        # The guard must not reject the legal case sitting next to it.
        self.parse(p.ipfix([p.template_set([(310, [(8, 4), (12, 4)]),
                                            (311, [(7, 2), (11, 2)]),
                                            (312, [(4, 1)])])]))
        for tid, count in ((310, 2), (311, 2), (312, 1)):
            with self.subTest(tid=tid):
                fields, _ = self.store.get("10.0.0.1", 0, tid)
                self.assertEqual(len(fields), count)


class DualStackTemplatesKeepTheirAddresses(unittest.TestCase):
    """IE 27/28 normalise to the same keys as IE 8/12, being the same idea.

    An exporter emitting one template for both families zero-fills the one the
    flow does not use. Assigning blindly, the later field wins and a real IPv4
    conversation is delivered as "::" -> "::". The `or` fallback in
    flow_endpoints cannot save it, because "::" is truthy.
    """

    FIELDS = [(8, 4), (12, 4), (27, 16), (28, 16), (9, 1), (29, 1), (4, 1)]

    def decode(self, payload):
        store, stats = TemplateStore(), Counter()
        parse_v9_or_ipfix(p.ipfix([p.template_set([(320, self.FIELDS)])]),
                          "10.0.0.1", store, stats)
        _, records, _ = parse_v9_or_ipfix(
            p.ipfix([p.data_set(320, payload)], seq=1), "10.0.0.1", store, stats)
        return records[0]

    def test_an_ipv4_flow_keeps_its_ipv4_addresses(self):
        rec = self.decode(b"\xc0\xa8\x01\x0a" + b"\x08\x08\x08\x08"
                          + b"\x00" * 32 + b"\x18" + b"\x00" + b"\x06")
        self.assertEqual(rec["src_addr"], "192.168.1.10")
        self.assertEqual(rec["dst_addr"], "8.8.8.8")
        self.assertEqual(rec["src_mask"], 24)

    def test_an_ipv6_flow_keeps_its_ipv6_addresses(self):
        v6_src = bytes.fromhex("20010db8000000000000000000000001")
        v6_dst = bytes.fromhex("20010db8000000000000000000000002")
        rec = self.decode(b"\x00" * 8 + v6_src + v6_dst
                          + b"\x00" + b"\x40" + b"\x06")
        self.assertEqual(rec["src_addr"], "2001:db8::1")
        self.assertEqual(rec["dst_addr"], "2001:db8::2")
        self.assertEqual(rec["src_mask"], 64)

    def test_a_zero_fill_does_not_erase_a_populated_mask(self):
        # The ordinary dual-stack exporter: real IPv4 mask, IPv6 half zeroed.
        rec = self.masks(b"\x18\x00")
        self.assertEqual(rec["src_mask"], 24)

    def test_a_legitimate_zero_mask_survives(self):
        # A default route really is /0, and both halves agree here.
        rec = self.masks(b"\x00\x00")
        self.assertEqual(rec["src_mask"], 0)

    def test_a_nonzero_padded_unused_family_wins_and_that_is_accepted(self):
        # The one case the guard gets wrong: an exporter padding the unused
        # family with 0xFF rather than zeros beats a genuine /0. Dropping zero
        # from UNSPECIFIED would fix this and break the common case above, and
        # such an exporter also emits 255.255.255.255 addresses that no rule
        # catches. Asserted so the trade is visible rather than rediscovered.
        rec = self.masks(b"\xff\x00")
        self.assertEqual(rec["src_mask"], 255)

    def masks(self, payload):
        store, stats = TemplateStore(), Counter()
        parse_v9_or_ipfix(p.ipfix([p.template_set([(322, [(9, 1), (29, 1)])])]),
                          "10.0.0.1", store, stats)
        _, records, _ = parse_v9_or_ipfix(
            p.ipfix([p.data_set(322, payload)], seq=1), "10.0.0.1", store, stats)
        return records[0]

    def test_a_template_without_repeats_is_unaffected(self):
        store, stats = TemplateStore(), Counter()
        parse_v9_or_ipfix(p.ipfix([p.template_set([(321, p.FLOW_FIELDS)])]),
                          "10.0.0.1", store, stats)
        _, records, _ = parse_v9_or_ipfix(
            p.ipfix([p.data_set(321, p.flow_payload())], seq=1),
            "10.0.0.1", store, stats)
        self.assertEqual(records[0]["src_addr"], "192.168.1.10")


class SamplingIsScopedToAnObservationDomain(unittest.TestCase):
    """One chassis can run several domains and sample them differently.

    Keyed by exporter alone, an unsampled second domain deletes the first
    domain's rate, after which every flow from it under-reports its traffic by
    that factor, silently, because the counts still look like counts.
    """

    def setUp(self):
        self.watch = SamplingWatch()

    def test_an_unsampled_domain_does_not_clear_anothers_rate(self):
        self.watch.note("10.0.0.1", 1, {"sampling_interval": 1000})
        self.watch.note("10.0.0.1", 2, {"sampling_interval": 1})
        self.assertEqual(self.watch.rate_for("10.0.0.1", 1), 1000)
        self.assertEqual(self.watch.rate_for("10.0.0.1", 2), 1)

    def test_two_domains_hold_two_rates(self):
        self.watch.note("10.0.0.1", 1, {"sampling_interval": 100})
        self.watch.note("10.0.0.1", 2, {"sampling_interval": 200})
        self.assertEqual(self.watch.rate_for("10.0.0.1", 1), 100)
        self.assertEqual(self.watch.rate_for("10.0.0.1", 2), 200)

    def test_asking_without_a_domain_answers_when_they_agree(self):
        self.watch.note("10.0.0.1", 1, {"sampling_interval": 100})
        self.watch.note("10.0.0.1", 2, {"sampling_interval": 100})
        self.assertEqual(self.watch.rate_for("10.0.0.1"), 100)

    def test_and_declines_to_guess_when_they_do_not(self):
        self.watch.note("10.0.0.1", 1, {"sampling_interval": 100})
        self.watch.note("10.0.0.1", 2, {"sampling_interval": 200})
        self.assertEqual(self.watch.rate_for("10.0.0.1"), 1)

    def test_the_event_names_the_domain_it_is_about(self):
        event = self.watch.note("10.0.0.1", 7, {"sampling_interval": 1000})
        self.assertEqual(event.domain, 7)
        self.assertIn("domain 7", str(event))

    def test_the_decoder_scopes_the_rate_to_the_message(self):
        decoder = Decoder()
        for domain in (1, 2):
            decoder.decode(p.ipfix([p.ipfix_options_template(
                400 + domain, [(145, 4)], [(34, 4)])], domain=domain), "10.0.0.1")
        decoder.decode(p.ipfix([p.data_set(401, struct.pack("!II", 1, 1000))],
                               domain=1, seq=1), "10.0.0.1")
        decoder.decode(p.ipfix([p.data_set(402, struct.pack("!II", 2, 1))],
                               domain=2, seq=2), "10.0.0.1")
        self.assertEqual(decoder.sampling_rate("10.0.0.1", 1), 1000)
        self.assertEqual(decoder.sampling_rate("10.0.0.1", 2), 1)


class MisalignedV9OptionsTemplates(unittest.TestCase):
    """v9 declares the two halves as byte lengths, not as field counts.

    Both hold whole 4-byte field specifications, so a length that is not a
    multiple of 4 leaves the option specs misaligned by the remainder and
    stores a template of nonsense: the same poisoning as a truncated one.
    """

    def setUp(self):
        self.store = TemplateStore()
        self.stats = Counter()

    def raw_options(self, tid, scope_len, opt_len, specs):
        body = struct.pack("!HHH", tid, scope_len, opt_len) + specs
        return p.v9([p.raw_set(1, body)])

    def test_a_scope_length_that_is_not_four_aligned_is_refused(self):
        specs = spec(145, 4) + spec(34, 4) + spec(35, 1)
        parse_v9_or_ipfix(self.raw_options(330, 6, 4, specs),
                          "10.0.0.1", self.store, self.stats)
        self.assertEqual(self.store.get("10.0.0.1", 0, 330), (None, False))

    def test_an_option_length_that_is_not_four_aligned_is_refused(self):
        specs = spec(145, 4) + spec(34, 4) + spec(35, 1)
        parse_v9_or_ipfix(self.raw_options(331, 4, 6, specs),
                          "10.0.0.1", self.store, self.stats)
        self.assertEqual(self.store.get("10.0.0.1", 0, 331), (None, False))

    def test_lengths_that_overrun_the_set_are_refused(self):
        parse_v9_or_ipfix(self.raw_options(332, 4, 400, spec(145, 4)),
                          "10.0.0.1", self.store, self.stats)
        self.assertEqual(self.store.get("10.0.0.1", 0, 332), (None, False))

    def test_a_well_formed_v9_options_template_still_works(self):
        parse_v9_or_ipfix(
            p.v9([p.v9_options_template(333, [(145, 4)], [(34, 4)])]),
            "10.0.0.1", self.store, self.stats)
        fields, is_options = self.store.get("10.0.0.1", 0, 333)
        self.assertTrue(is_options)
        self.assertEqual([f[0] for f in fields],
                         ["template_id", "sampling_interval"])


class AMessageIsNeverFalsy(unittest.TestCase):
    """__len__ counts flows, and a message with none is not a failure.

    Template sets, option records and sequence gaps all arrive in messages
    carrying no flows, and an exporter's first datagrams are routinely all
    template. Left to __len__, ``if message:`` discards every one of them.
    """

    def test_a_template_only_message_is_true(self):
        decoder = Decoder()
        message = decoder.decode(
            p.ipfix([p.template_set([(340, p.FLOW_FIELDS)])]), "10.0.0.1")
        self.assertIsNotNone(message)
        self.assertTrue(message)
        self.assertEqual(len(message), 0)

    def test_an_options_only_message_is_true(self):
        decoder = Decoder()
        decoder.decode(
            p.ipfix([p.ipfix_options_template(341, [(145, 4)], [(34, 4)])]),
            "10.0.0.1")
        message = decoder.decode(
            p.ipfix([p.data_set(341, struct.pack("!II", 9, 1000))], seq=1),
            "10.0.0.1")
        self.assertTrue(message)
        self.assertEqual(len(message.options), 1)


class NothingGrowsWithoutBound(unittest.TestCase):
    """Every per-exporter table is keyed by a forgeable source address.

    A UDP source address is whatever the sender typed, so anything keyed by it
    and never evicted is a memory leak that anyone able to reach the socket can
    pull on. values.py already caps its caches for exactly this reason.
    """

    def test_the_template_store_evicts_the_least_recently_used(self):
        store = TemplateStore(max_templates=4)
        for i in range(20):
            store.put("10.0.0.%d" % i, 0, 300, [("src_addr", "ipv4", 4)])
        self.assertEqual(len(store.templates), 4)
        self.assertEqual(store.evicted, 16)

    def test_a_template_still_in_use_survives_a_flood(self):
        store = TemplateStore(max_templates=4)
        store.put("10.0.0.1", 0, 300, [("src_addr", "ipv4", 4)])
        for i in range(20):
            store.put("192.0.2.%d" % i, 0, 300, [("dst_addr", "ipv4", 4)])
            store.get("10.0.0.1", 0, 300)      # reading counts as use
        fields, _ = store.get("10.0.0.1", 0, 300)
        self.assertEqual(fields, [("src_addr", "ipv4", 4)])

    def test_sequence_streams_are_capped(self):
        watch = SequenceWatch(max_streams=4)
        for i in range(20):
            watch.observe("10.0.0.%d" % i, 0, 10, 1, 5)
        self.assertEqual(len(watch.streams), 4)
        self.assertEqual(watch.evicted, 16)

    def test_evicting_a_stream_takes_its_counters_with_it(self):
        # missed and units are keyed by stream too, so capping only `streams`
        # would leave the leak in place through them.
        watch = SequenceWatch(max_streams=2)
        watch.observe("10.0.0.1", 0, 10, 1, 5)
        key = ("10.0.0.1", 0, 10)
        watch.missed[key] = 99
        watch.units[key] = "data records"
        for i in range(10):
            watch.observe("192.0.2.%d" % i, 0, 10, 1, 5)
        self.assertNotIn(key, watch.streams)
        self.assertNotIn(key, watch.missed)
        self.assertNotIn(key, watch.units)

    def test_the_warned_table_is_capped(self):
        watch = SequenceWatch(max_streams=3)
        for i in range(20):
            watch._warned["10.0.0.%d" % i] = True
            watch.observe("10.0.0.%d" % i, 0, 10, 1, 5)
        self.assertLessEqual(len(watch._warned), 3)

    def test_sampling_rates_are_capped(self):
        watch = SamplingWatch(max_streams=4)
        for i in range(20):
            watch.note("10.0.0.%d" % i, 0, {"sampling_interval": 100})
        self.assertEqual(len(watch.rates), 4)
        self.assertEqual(watch.evicted, 16)

    def test_the_service_cache_is_capped(self):
        # The protocol number comes off the wire and can be any width the
        # template declares, so it is the unbounded axis, not the port.
        with mock.patch.object(values, "MAX_SERVICE_CACHE", 8):
            values._service_cache.clear()
            for proto in range(100):
                values.service_name(80, proto)
            self.assertLessEqual(len(values._service_cache), 8)
        values._service_cache.clear()


class TheEventQueueIsBounded(unittest.TestCase):
    """A collector on an open port receives things that are not NetFlow.

    Each raises a DecodeError, and neither Collector.flows() nor the README's
    quickstart drains them, so without a ceiling the queue would accumulate one
    per bad datagram for the life of the process.
    """

    JUNK = b"\xff\xff\x00\x08"

    def test_junk_does_not_accumulate_for_ever(self):
        decoder = Decoder()
        for _ in range(MAX_PENDING_EVENTS + 500):
            decoder.decode(self.JUNK, "10.0.0.1")
        self.assertEqual(len(decoder._events), MAX_PENDING_EVENTS)

    def test_and_the_drops_are_counted_rather_than_silent(self):
        decoder = Decoder()
        for _ in range(MAX_PENDING_EVENTS + 500):
            decoder.decode(self.JUNK, "10.0.0.1")
        self.assertEqual(decoder.stats["events_dropped"], 500)

    def test_taking_the_events_still_empties_the_queue(self):
        decoder = Decoder()
        for _ in range(10):
            decoder.decode(self.JUNK, "10.0.0.1")
        self.assertEqual(len(decoder.take_events()), 10)
        self.assertEqual(decoder.take_events(), [])


if __name__ == "__main__":
    unittest.main()
