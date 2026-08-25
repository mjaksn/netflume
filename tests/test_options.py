"""Option records describe the exporter, not traffic, and must not be flows.

Options data records describe the exporter rather than its traffic, and
would otherwise inherit: an option data record decoded into the flow list looks
like a flow with no addresses, and inflates every count downstream.
"""

import struct
import unittest
from collections import Counter

from netflume import SamplingWatch, sampling_rate
from netflume.events import SamplingChange
from netflume.parse import TemplateStore, parse_v5, parse_v9_or_ipfix

from . import packets as p


class OptionRecordsAreNotFlows(unittest.TestCase):
    def setUp(self):
        self.store = TemplateStore()
        self.stats = Counter()

    def parse(self, msg, exporter="10.0.0.1"):
        return parse_v9_or_ipfix(msg, exporter, self.store, self.stats)

    def test_ipfix_option_record_is_kept_separate(self):
        msg = p.ipfix([p.ipfix_options_template(300, [(145, 4)], [(34, 4)]),
                       p.data_set(300, struct.pack("!II", 999, 1000))])
        _, records, opts = self.parse(msg)
        self.assertEqual(records, [])
        self.assertEqual(len(opts), 1)
        self.assertEqual(opts[0]["sampling_interval"], 1000)
        self.assertEqual(opts[0]["template_id"], 999)

    def test_v9_option_record_is_kept_separate(self):
        msg = p.v9([p.v9_options_template(301, [(145, 4)], [(34, 4)]),
                    p.data_set(301, struct.pack("!II", 999, 500))])
        _, records, opts = self.parse(msg)
        self.assertEqual(records, [])
        self.assertEqual(len(opts), 1)
        self.assertEqual(opts[0]["sampling_interval"], 500)

    def test_flows_and_options_in_one_message_are_split(self):
        msg = p.ipfix([p.data_template(400, p.FLOW_FIELDS),
                       p.ipfix_options_template(401, [(145, 4)], [(34, 4)]),
                       p.data_set(400, p.flow_payload()),
                       p.data_set(401, struct.pack("!II", 1, 64))])
        _, records, opts = self.parse(msg)
        self.assertEqual(len(records), 1)
        self.assertEqual(len(opts), 1)

    def test_an_options_template_is_counted_as_learned(self):
        self.parse(p.ipfix([p.ipfix_options_template(300, [(145, 4)], [(34, 4)])]))
        self.assertEqual(self.stats["templates_new"], 1)

    def test_an_option_set_before_its_template_defers_and_recovers(self):
        payload = struct.pack("!II", 999, 1000)
        _, records, opts = self.parse(p.ipfix([p.data_set(300, payload)]))
        self.assertEqual((records, opts), ([], []))
        self.assertEqual(self.stats["deferred"], 1)

        self.parse(p.ipfix([p.ipfix_options_template(300, [(145, 4)], [(34, 4)])]))
        self.assertTrue(self.store.get("10.0.0.1", 0, 300)[1])
        _, records, opts = self.parse(p.ipfix([p.data_set(300, payload)]))
        self.assertEqual(records, [])
        self.assertEqual(opts[0]["sampling_interval"], 1000)
        self.assertEqual(self.stats["deferred"], 1)


class OptionScopeAlignment(unittest.TestCase):
    """A scope field of any width must not shift the option fields after it."""

    def parse(self, msg):
        return parse_v9_or_ipfix(msg, "10.0.0.1", TemplateStore(), Counter())

    def test_two_byte_scope(self):
        msg = p.ipfix([p.ipfix_options_template(301, [(145, 2)], [(34, 4)]),
                       p.data_set(301, struct.pack("!HI", 999, 1000))])
        _, _, opts = self.parse(msg)
        self.assertEqual(opts[0]["template_id"], 999)
        self.assertEqual(opts[0]["sampling_interval"], 1000)

    def test_mixed_option_field_widths(self):
        msg = p.ipfix([p.ipfix_options_template(302, [(149, 4)],
                                                [(305, 4), (306, 2)]),
                       p.data_set(302, struct.pack("!IIH", 7, 1, 999))])
        _, _, opts = self.parse(msg)
        self.assertEqual(opts[0]["sampling_packet_interval"], 1)
        self.assertEqual(opts[0]["sampling_packet_space"], 999)
        self.assertEqual(sampling_rate(opts[0]), 1000)

    def test_an_unknown_scope_element_still_leaves_the_record_aligned(self):
        msg = p.ipfix([p.ipfix_options_template(303, [(9999, 8)], [(34, 4)]),
                       p.data_set(303, struct.pack("!QI", 1, 2000))])
        _, _, opts = self.parse(msg)
        self.assertEqual(opts[0]["sampling_interval"], 2000)

    def test_a_v9_scope_length_larger_than_the_set_does_not_reach_outside(self):
        # A malformed scope length must not escape as struct.error, and must
        # not reach past the end of its own set to read the next one either.
        body = struct.pack("!HHH", 304, 400, 4) + p.field_specs([(34, 4)])
        bad = struct.pack("!HH", 1, 4 + len(body)) + body
        hdr, records, opts = self.parse(p.v9([bad]))
        self.assertIsNotNone(hdr)
        self.assertEqual((records, opts), ([], []))


class SamplingRateFromARecord(unittest.TestCase):
    """Every form an exporter uses to advertise how much it is leaving out."""

    CASES = [
        ({"sampling_interval": 1000}, 1000, "v9 samplingInterval"),
        ({"sampler_interval": 256}, 256, "samplerRandomInterval"),
        ({"sampling_packet_interval": 1, "sampling_packet_space": 999}, 1000,
         "IPFIX interval/space"),
        ({"sampling_packet_interval": 2, "sampling_packet_space": 8}, 5,
         "IPFIX interval/space, 2 in 10"),
        ({"sampling_size": 1, "sampling_population": 100}, 100,
         "IPFIX size/population"),
        ({"sampling_interval": 1}, 1, "an interval of 1, stating unsampled"),
        ({"sampling_packet_interval": 1, "sampling_packet_space": 0}, 1,
         "interval with a space of 0, stating unsampled"),
        ({"sampling_size": 5, "sampling_population": 5}, 1,
         "size equal to population, stating unsampled"),
        ({"sampling_interval": 0}, None, "an interval of 0, which is padding"),
        ({"sampling_packet_interval": 4}, None, "an interval with no space"),
        ({"sampling_population": 1000}, None, "a population with no size"),
        ({"template_id": 999}, None, "an unrelated option record"),
        ({}, None, "an empty record"),
    ]

    def test_every_advertised_form(self):
        for rec, want, label in self.CASES:
            with self.subTest(label):
                self.assertEqual(sampling_rate(rec), want)

    def test_silence_and_unsampled_are_different_answers(self):
        # None is "this record says nothing"; 1 is "this record says none is
        # being dropped". A caller holding a stale rate must tell them apart.
        self.assertIsNone(sampling_rate({"if_name": "eth0"}))
        self.assertEqual(sampling_rate({"sampling_interval": 1}), 1)


class SamplingWatchEvents(unittest.TestCase):
    def setUp(self):
        self.watch = SamplingWatch()

    def test_a_new_rate_is_an_event(self):
        event = self.watch.note("10.0.0.1", 0, {"sampling_interval": 1000})
        self.assertIsInstance(event, SamplingChange)
        self.assertEqual(event.rate, 1000)
        self.assertIsNone(event.previous)

    def test_the_same_rate_repeated_is_not(self):
        self.watch.note("10.0.0.1", 0, {"sampling_interval": 1000})
        self.assertIsNone(self.watch.note("10.0.0.1", 0, {"sampling_interval": 1000}))
        self.assertEqual(len(self.watch.take_events()), 1)

    def test_a_changed_rate_is_an_event_carrying_the_old_one(self):
        self.watch.note("10.0.0.1", 0, {"sampling_interval": 1000})
        event = self.watch.note("10.0.0.1", 0, {"sampling_interval": 500})
        self.assertEqual((event.rate, event.previous), (500, 1000))

    def test_rates_are_tracked_per_exporter_and_domain(self):
        self.watch.note("10.0.0.1", 0, {"sampling_interval": 500})
        self.watch.note("10.0.0.2", 0, {"sampling_interval": 1000})
        self.assertEqual(self.watch.rates,
                         {("10.0.0.1", 0): 500, ("10.0.0.2", 0): 1000})

    def test_an_unrelated_record_does_not_clear_a_known_rate(self):
        self.watch.note("10.0.0.1", 0, {"sampling_interval": 1000})
        self.watch.note("10.0.0.1", 0, {"if_name": "eth0", "template_id": 5})
        self.assertEqual(self.watch.rate_for("10.0.0.1"), 1000)

    def test_an_explicit_interval_of_one_clears_a_stale_rate(self):
        self.watch.note("10.0.0.1", 0, {"sampling_interval": 1000})
        event = self.watch.note("10.0.0.1", 0, {"sampling_interval": 1})
        self.assertEqual(self.watch.rates, {})
        self.assertEqual((event.rate, event.previous), (1, 1000))

    def test_the_ipfix_form_of_unsampled_clears_it_too(self):
        self.watch.note("10.0.0.2", 0, {"sampling_interval": 500})
        self.watch.note("10.0.0.2", 0, {"sampling_packet_interval": 1,
                                        "sampling_packet_space": 0})
        self.assertEqual(self.watch.rates, {})

    def test_an_exporter_that_was_never_sampling_stays_silent(self):
        self.assertIsNone(self.watch.note("10.0.0.2", 0, {"sampling_interval": 1}))
        self.assertEqual(self.watch.take_events(), [])

    def test_clearing_one_exporter_leaves_the_other_alone(self):
        self.watch.note("10.0.0.1", 0, {"sampling_interval": 100})
        self.watch.note("10.0.0.2", 0, {"sampling_interval": 200})
        self.watch.note("10.0.0.1", 0, {"sampling_interval": 1})
        self.assertEqual(self.watch.rates, {("10.0.0.2", 0): 200})

    def test_rate_for_an_unheard_of_exporter_is_one_not_none(self):
        # "Assume it is sending everything" is both the common case and the
        # only safe reading; None would push the guess onto every caller.
        self.assertEqual(self.watch.rate_for("10.9.9.9"), 1)

    def test_events_are_taken_once(self):
        self.watch.note("10.0.0.1", 0, {"sampling_interval": 1000})
        self.assertEqual(len(self.watch.take_events()), 1)
        self.assertEqual(self.watch.take_events(), [])

    def test_the_event_explains_itself_in_words(self):
        event = self.watch.note("10.0.0.1", 0, {"sampling_interval": 1000})
        text = str(event)
        self.assertIn("1-in-1000", text)
        self.assertIn("1000x higher", text)

    def test_nothing_is_written_to_stdout_or_stderr(self):
        # Reachable as an object, not only as a log line.
        import contextlib
        import io
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            self.watch.note("10.0.0.1", 0, {"sampling_interval": 1000})
        self.assertEqual((out.getvalue(), err.getvalue()), ("", ""))

    def test_it_reaches_the_log_as_well(self):
        with self.assertLogs("netflume.sampling", "WARNING") as caught:
            self.watch.note("10.0.0.1", 0, {"sampling_interval": 1000})
        self.assertIn("1-in-1000", caught.output[0])


class V5HeaderSampling(unittest.TestCase):
    def test_the_header_rate_is_reported_as_an_option_record(self):
        _, _, opts = parse_v5(p.v5(sampling_word=(1 << 14) | 100), "10.0.0.1")
        self.assertEqual(sampling_rate(opts[0]), 100)

    def test_so_one_shape_serves_all_three_versions(self):
        watch = SamplingWatch()
        _, _, opts = parse_v5(p.v5(sampling_word=(2 << 14) | 250), "10.0.0.1")
        for opt in opts:
            watch.note("10.0.0.1", 0, opt)
        self.assertEqual(watch.rate_for("10.0.0.1"), 250)


if __name__ == "__main__":
    unittest.main()
