"""The stateful decoding layer: messages, counters, and never raising."""

import struct
import unittest

from netflume import Decoder, Flow, Message, TemplateStore
from netflume.events import (
    DecodeError,
    ExportGap,
    SamplingChange,
    TemplateLearned,
)

from . import packets as p


class DecodingOneDatagram(unittest.TestCase):
    def setUp(self):
        self.decoder = Decoder()

    def test_a_v5_datagram(self):
        message = self.decoder.decode(p.v5_message(count=3), "10.0.0.1")
        self.assertIsInstance(message, Message)
        self.assertEqual(message.version, 5)
        self.assertEqual(message.exporter, "10.0.0.1")
        self.assertEqual(len(message), 3)

    def test_a_template_only_datagram_is_not_a_failure(self):
        # An exporter's first datagrams are routinely all template. A caller
        # must not read "no flows" as "something went wrong".
        message = self.decoder.decode(
            p.ipfix([p.data_template(400, p.FLOW_FIELDS)]), "10.0.0.1")
        self.assertIsNotNone(message)
        self.assertEqual(message.flows, [])
        self.assertEqual(self.decoder.stats["templates_new"], 1)

    def test_templates_persist_between_calls(self):
        self.decoder.decode(p.ipfix([p.data_template(400, p.FLOW_FIELDS)]),
                            "10.0.0.1")
        message = self.decoder.decode(
            p.ipfix([p.data_set(400, p.flow_payload())]), "10.0.0.1")
        self.assertEqual(len(message.flows), 1)

    def test_one_decoder_serves_several_exporters(self):
        for exporter in ("10.0.0.1", "10.0.0.2"):
            self.decoder.decode(p.ipfix([p.data_template(400, p.FLOW_FIELDS)]),
                                exporter)
        for exporter in ("10.0.0.1", "10.0.0.2"):
            message = self.decoder.decode(
                p.ipfix([p.data_set(400, p.flow_payload())]), exporter)
            self.assertEqual(len(message.flows), 1)

    def test_typed_flows_are_built_on_demand(self):
        self.decoder.decode(p.ipfix([p.data_template(400, p.TIMED_FLOW_FIELDS)]),
                            "10.0.0.1")
        message = self.decoder.decode(
            p.ipfix([p.data_set(400, p.timed_flow_payload())]), "10.0.0.1")
        self.assertIsInstance(message.flows[0], dict)
        flow = message.typed_flows()[0]
        self.assertIsInstance(flow, Flow)
        self.assertEqual(flow.start, 1700000000.0)

    def test_the_flows_shortcut(self):
        self.decoder.decode(p.ipfix([p.data_template(400, p.FLOW_FIELDS)]),
                            "10.0.0.1")
        data = p.ipfix([p.data_set(400, p.flow_payload())])
        self.assertIsInstance(self.decoder.flows(data, "10.0.0.1")[0], dict)
        self.assertIsInstance(
            self.decoder.flows(data, "10.0.0.1", typed=True)[0], Flow)


class BadDatagramsDoNotRaise(unittest.TestCase):
    """A decoder that dies on one bad packet is useless on a real network."""

    def setUp(self):
        self.decoder = Decoder()

    def test_an_empty_datagram(self):
        self.assertIsNone(self.decoder.decode(b"", "10.0.0.1"))
        self.assertEqual(self.decoder.stats["malformed"], 1)

    def test_a_datagram_of_one_byte(self):
        self.assertIsNone(self.decoder.decode(b"\x00", "10.0.0.1"))

    def test_a_truncated_header(self):
        self.assertIsNone(self.decoder.decode(b"\x00\x0a\x00\x10", "10.0.0.1"))
        self.assertEqual(self.decoder.stats["malformed"], 1)

    def test_an_unsupported_version_is_counted_apart_from_malformation(self):
        # sFlow on the NetFlow port is the usual cause, and it is a
        # configuration mistake rather than corruption.
        self.assertIsNone(self.decoder.decode(struct.pack("!HH", 3, 0),
                                              "10.0.0.1"))
        self.assertEqual(self.decoder.stats["unsupported_version"], 1)
        self.assertEqual(self.decoder.stats["malformed"], 0)

    def test_random_bytes_claiming_to_be_ipfix(self):
        junk = struct.pack("!H", 10) + bytes(range(60))
        self.decoder.decode(junk, "10.0.0.1")     # must not raise

    def test_every_prefix_of_a_valid_message_is_survivable(self):
        msg = p.ipfix([p.data_template(400, p.FLOW_FIELDS),
                       p.ipfix_options_template(300, [(145, 4)], [(34, 4)]),
                       p.data_set(400, p.flow_payload())])
        for cut in range(len(msg)):
            self.decoder.decode(msg[:cut], "10.0.0.1")

    def test_the_datagram_is_still_counted_as_received(self):
        self.decoder.decode(b"\x00", "10.0.0.1")
        self.assertEqual(self.decoder.stats["packets"], 1)
        self.assertEqual(self.decoder.stats["bytes_rx"], 1)

    def test_a_failure_is_reported_as_an_event(self):
        self.decoder.decode(struct.pack("!HH", 3, 0), "10.0.0.1")
        events = self.decoder.take_events()
        self.assertEqual(len(events), 1)
        self.assertIsInstance(events[0], DecodeError)
        self.assertEqual(events[0].reason, "unsupported")
        self.assertIn("version 3", str(events[0]))


class Counters(unittest.TestCase):
    def test_the_running_totals(self):
        decoder = Decoder()
        msg = p.ipfix([p.data_template(400, p.FLOW_FIELDS),
                       p.ipfix_options_template(300, [(145, 4)], [(34, 4)]),
                       p.data_set(400, p.flow_payload() * 2),
                       p.data_set(300, struct.pack("!II", 999, 1000))])
        decoder.decode(msg, "10.0.0.1")
        stats = decoder.stats
        self.assertEqual(stats["packets"], 1)
        self.assertEqual(stats["bytes_rx"], len(msg))
        self.assertEqual(stats["flows"], 2)
        self.assertEqual(stats["option_records"], 1)
        self.assertEqual(stats["templates_new"], 2)
        self.assertEqual(stats["v10_msgs"], 1)

    def test_option_records_are_not_counted_as_flows(self):
        decoder = Decoder()
        decoder.decode(p.ipfix([p.ipfix_options_template(300, [(145, 4)],
                                                         [(34, 4)]),
                                p.data_set(300, struct.pack("!II", 9, 1000))]),
                       "10.0.0.1")
        self.assertEqual(decoder.stats["flows"], 0)
        self.assertEqual(decoder.stats["option_records"], 1)

    def test_versions_are_counted_apart(self):
        decoder = Decoder()
        decoder.decode(p.v5_message(count=1), "10.0.0.1")
        decoder.decode(p.v9([]), "10.0.0.1")
        decoder.decode(p.ipfix([]), "10.0.0.1")
        self.assertEqual(decoder.stats["v5_msgs"], 1)
        self.assertEqual(decoder.stats["v9_msgs"], 1)
        self.assertEqual(decoder.stats["v10_msgs"], 1)


class SamplingIsFollowedAutomatically(unittest.TestCase):
    def setUp(self):
        self.decoder = Decoder()
        self.decoder.decode(
            p.ipfix([p.ipfix_options_template(300, [(145, 4)], [(34, 4)]),
                     p.data_set(300, struct.pack("!II", 999, 1000)),
                     p.data_template(400, p.FLOW_FIELDS)]), "10.0.0.1")

    def test_the_rate_is_learned_from_the_option_record(self):
        self.assertEqual(self.decoder.sampling_rate("10.0.0.1"), 1000)

    def test_it_is_attached_to_later_messages(self):
        message = self.decoder.decode(
            p.ipfix([p.data_set(400, p.flow_payload())]), "10.0.0.1")
        self.assertEqual(message.sampling_rate, 1000)
        self.assertEqual(message.typed_flows()[0].sampling_rate, 1000)

    def test_and_raised_as_an_event(self):
        events = [e for e in self.decoder.take_events()
                  if isinstance(e, SamplingChange)]
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].rate, 1000)

    def test_an_unheard_of_exporter_is_assumed_unsampled(self):
        self.assertEqual(self.decoder.sampling_rate("10.9.9.9"), 1)


class SequenceIsFollowedAutomatically(unittest.TestCase):
    def test_a_gap_appears_on_the_message_and_as_an_event(self):
        decoder = Decoder()
        for seq in (0, 3, 6):
            decoder.decode(p.v5_message(seq=seq, count=3), "10.0.0.1")
        decoder.take_events()
        message = decoder.decode(p.v5_message(seq=15, count=3), "10.0.0.1")
        self.assertEqual(message.gap, 6)
        self.assertEqual(decoder.stats["missed_exports"], 6)
        gaps = [e for e in decoder.take_events() if isinstance(e, ExportGap)]
        self.assertEqual(len(gaps), 1)
        self.assertEqual(gaps[0].missed, 6)

    def test_a_clean_stream_reports_nothing(self):
        decoder = Decoder()
        for seq in (0, 3, 6, 9):
            message = decoder.decode(p.v5_message(seq=seq, count=3), "10.0.0.1")
            self.assertEqual(message.gap, 0)
        self.assertEqual(decoder.export_gaps(), [])

    def test_cumulative_gaps_can_be_read_at_any_time(self):
        decoder = Decoder()
        for seq in (0, 3, 6, 15):
            decoder.decode(p.v5_message(seq=seq, count=3), "10.0.0.1")
        gap = decoder.export_gaps()[0]
        self.assertEqual((gap.exporter, gap.missed, gap.unit),
                         ("10.0.0.1", 6, "flow records"))

    def test_tracking_can_be_turned_off(self):
        decoder = Decoder(track_sequence=False, track_sampling=False)
        for seq in (0, 3, 6, 15):
            message = decoder.decode(p.v5_message(seq=seq, count=3), "10.0.0.1")
        self.assertEqual(message.gap, 0)
        self.assertEqual(decoder.export_gaps(), [])
        self.assertEqual(decoder.sampling_rate("10.0.0.1"), 1)


class EventBookkeeping(unittest.TestCase):
    def test_events_are_taken_once(self):
        decoder = Decoder()
        decoder.decode(b"\x00", "10.0.0.1")
        self.assertEqual(len(decoder.take_events()), 1)
        self.assertEqual(decoder.take_events(), [])

    def test_a_healthy_stream_produces_nothing_but_its_templates(self):
        # A first template is news and is an event. Nothing else on a stream
        # that is behaving is, which is the property this has always held.
        decoder = Decoder()
        datagram = p.ipfix([p.data_template(400, p.FLOW_FIELDS),
                            p.data_set(400, p.flow_payload())])
        decoder.decode(datagram, "10.0.0.1")
        events = decoder.take_events()
        self.assertEqual([type(e) for e in events], [TemplateLearned])

    def test_a_settled_stream_produces_none(self):
        # The same datagram again: the exporter is resending a template this
        # decoder already holds, which is what they all do and is not news.
        decoder = Decoder()
        datagram = p.ipfix([p.data_template(400, p.FLOW_FIELDS),
                            p.data_set(400, p.flow_payload())])
        decoder.decode(datagram, "10.0.0.1")
        decoder.take_events()
        decoder.decode(datagram, "10.0.0.1")
        self.assertEqual(decoder.take_events(), [])

    def test_nothing_is_printed(self):
        import contextlib
        import io
        out, err = io.StringIO(), io.StringIO()
        decoder = Decoder()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            decoder.decode(b"\x00", "10.0.0.1")
            decoder.decode(p.v5_message(sampling_word=(1 << 14) | 100),
                           "10.0.0.1")
        self.assertEqual((out.getvalue(), err.getvalue()), ("", ""))


class TemplateEvents(unittest.TestCase):
    def setUp(self):
        self.decoder = Decoder()

    def learned(self, datagram, exporter="10.0.0.1"):
        self.decoder.decode(datagram, exporter)
        return [e for e in self.decoder.take_events()
                if isinstance(e, TemplateLearned)]

    def test_a_template_datagram_raises_one(self):
        events = self.learned(p.ipfix([p.data_template(400, p.FLOW_FIELDS)]))
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].template_id, 400)
        self.assertEqual(events[0].exporter, "10.0.0.1")
        self.assertIsNone(events[0].previous)

    def test_the_fields_are_the_layout_records_are_read_through(self):
        events = self.learned(p.ipfix([p.data_template(400, p.FLOW_FIELDS)]))
        self.assertEqual([name for name, _kind, _len in events[0].fields],
                         ["src_addr", "dst_addr", "src_port", "dst_port",
                          "proto", "octets", "packets"])

    def test_a_v9_template_raises_one_too(self):
        events = self.learned(p.v9([p.v9_data_template(400, p.FLOW_FIELDS)],
                                   count=1))
        self.assertEqual([e.template_id for e in events], [400])

    def test_an_options_template_says_so(self):
        events = self.learned(
            p.ipfix([p.ipfix_options_template(300, [(145, 4)], [(34, 4)])]))
        self.assertEqual([e.options for e in events], [True])

    def test_several_templates_in_one_set_each_raise_one(self):
        events = self.learned(p.ipfix([p.template_set(
            [(400, p.FLOW_FIELDS), (401, p.FLOW_FIELDS[:3])])]))
        self.assertEqual([e.template_id for e in events], [400, 401])

    def test_a_redefinition_carries_the_layout_it_replaced(self):
        self.learned(p.ipfix([p.data_template(400, p.FLOW_FIELDS)]))
        events = self.learned(
            p.ipfix([p.data_template(400, p.FLOW_FIELDS[:3])], seq=1))
        self.assertEqual(len(events), 1)
        self.assertEqual(len(events[0].previous), len(p.FLOW_FIELDS))
        self.assertEqual(len(events[0].fields), 3)

    def test_two_exporters_sharing_an_id_are_two_templates(self):
        datagram = p.ipfix([p.data_template(400, p.FLOW_FIELDS)])
        self.assertEqual(len(self.learned(datagram, "10.0.0.1")), 1)
        self.assertEqual(len(self.learned(datagram, "10.0.0.2")), 1)

    def test_v5_raises_none(self):
        self.assertEqual(self.learned(p.v5_message(count=3)), [])

    def test_a_template_survives_a_datagram_that_then_failed(self):
        # The set that raised is not the set that taught. A layout learned
        # from a sound template set is true whatever the rest of the datagram
        # turned out to be, and it is what every later record is read through,
        # so the event has to outlive the failure rather than be skipped by it.
        #
        # The raise is injected rather than found. parse_v9_or_ipfix is
        # hardened against every malformed datagram anybody has managed to
        # build, and tools/fuzz.py exists to keep it that way, so there is no
        # honest set of bytes that parses one set and then throws.
        class Exploding(TemplateStore):
            def get(self, *args):
                raise RuntimeError("boom")

        self.decoder.templates = Exploding()
        message = self.decoder.decode(
            p.ipfix([p.data_template(400, p.FLOW_FIELDS),
                     p.data_set(400, p.flow_payload())]), "10.0.0.1")
        events = self.decoder.take_events()
        self.assertIsNone(message)
        self.assertEqual([e.template_id for e in events
                          if isinstance(e, TemplateLearned)], [400])
        self.assertTrue(any(isinstance(e, DecodeError) for e in events))


if __name__ == "__main__":
    unittest.main()
