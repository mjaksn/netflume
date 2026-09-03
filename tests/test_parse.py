"""Decoding the three wire formats: headers, records, templates, edges."""

import struct
import unittest
from collections import Counter

from netflume import parse
from netflume.events import TemplateLearned
from netflume.parse import TemplateStore, parse_message, parse_v5, parse_v9_or_ipfix

from . import packets as p


class DecodeValue(unittest.TestCase):
    def test_addresses(self):
        self.assertEqual(parse.decode_value(b"\x08\x08\x08\x08", "ipv4"), "8.8.8.8")
        self.assertEqual(parse.decode_value(b"\x20\x01" + b"\x00" * 14, "ipv6"),
                         "2001::")

    def test_mac(self):
        self.assertEqual(parse.decode_value(b"\x00\x1a\x2b\x3c\x4d\x5e", "mac"),
                         "00:1a:2b:3c:4d:5e")

    def test_string_is_trimmed_of_padding(self):
        self.assertEqual(parse.decode_value(b"eth0\x00\x00", "string"), "eth0")

    def test_uint_of_any_width(self):
        self.assertEqual(parse.decode_value(b"\x01\x00", "uint"), 256)
        self.assertEqual(parse.decode_value(b"\x00" * 7 + b"\x05", "uint"), 5)

    def test_wrong_width_for_the_kind_falls_back(self):
        # A three-byte "ipv4" is not one. Small buffers read as integers.
        self.assertEqual(parse.decode_value(b"\x01\x02\x03", "ipv4"), 66051)

    def test_long_unknown_values_become_hex(self):
        raw = bytes(range(12))
        self.assertEqual(parse.decode_value(raw, "auto"), raw.hex())

    def test_empty_value(self):
        self.assertEqual(parse.decode_value(b"", "uint"), 0)
        self.assertEqual(parse.decode_value(b"", "auto"), "")


class ParseV5(unittest.TestCase):
    def test_header_fields(self):
        hdr, records, opts = parse_v5(p.v5_message(seq=42), "10.0.0.1")
        self.assertEqual(hdr["version"], 5)
        self.assertEqual(hdr["sequence"], 42)
        self.assertEqual(hdr["exporter"], "10.0.0.1")
        self.assertEqual(hdr["unix_secs"], 1700000000)
        self.assertEqual(hdr["sys_uptime"], 100000)

    def test_engine_id_is_the_domain(self):
        hdr, _, _ = parse_v5(p.v5(engine_id=7), "10.0.0.1")
        self.assertEqual(hdr["domain"], 7)

    def test_records_decode(self):
        _, records, _ = parse_v5(p.v5_message(count=3), "10.0.0.1")
        self.assertEqual(len(records), 3)
        first = records[0]
        self.assertEqual(first["src_addr"], "192.168.1.10")
        self.assertEqual(first["dst_addr"], "8.8.8.8")
        self.assertEqual(first["next_hop"], "192.168.1.1")
        self.assertEqual(first["src_port"], 51000)
        self.assertEqual(first["dst_port"], 443)
        self.assertEqual(first["proto"], 6)
        self.assertEqual(first["octets"], 1500)
        self.assertEqual(first["packets"], 12)
        self.assertEqual(first["tcp_flags"], 0x18)
        self.assertEqual(first["src_mask"], 24)

    def test_a_short_datagram_yields_three_values(self):
        self.assertEqual(parse_v5(b"\x00\x05", "10.0.0.1"), (None, [], []))

    def test_a_claimed_count_beyond_the_bytes_stops_at_the_bytes(self):
        # The header says 10 records; only two are present.
        msg = p.v5(count=10, records=[p.v5_record(), p.v5_record()])
        _, records, _ = parse_v5(msg, "10.0.0.1")
        self.assertEqual(len(records), 2)

    def test_a_truncated_final_record_is_dropped_not_guessed(self):
        msg = p.v5(count=2, records=[p.v5_record(), p.v5_record()[:20]])
        _, records, _ = parse_v5(msg, "10.0.0.1")
        self.assertEqual(len(records), 1)

    def test_sampling_rides_in_the_header(self):
        _, _, opts = parse_v5(p.v5(sampling_word=(1 << 14) | 100), "10.0.0.1")
        self.assertEqual(opts, [{"sampling_interval": 100,
                                 "sampling_algorithm": 1}])

    def test_an_unsampled_header_says_nothing(self):
        # Every v5 datagram carries this word. Reporting "unsampled" each time
        # would swamp the option-record count with news of nothing.
        self.assertEqual(parse_v5(p.v5(sampling_word=0), "10.0.0.1")[2], [])
        self.assertEqual(parse_v5(p.v5(sampling_word=(1 << 14) | 1),
                                  "10.0.0.1")[2], [])


class ParseIPFIX(unittest.TestCase):
    def setUp(self):
        self.store = TemplateStore()
        self.stats = Counter()

    def parse(self, msg, exporter="10.0.0.1"):
        return parse_v9_or_ipfix(msg, exporter, self.store, self.stats)

    def test_header_fields(self):
        hdr, _, _ = self.parse(p.ipfix([], seq=9, domain=3))
        self.assertEqual(hdr["version"], 10)
        self.assertEqual(hdr["sequence"], 9)
        self.assertEqual(hdr["domain"], 3)
        self.assertEqual(hdr["unix_secs"], 1700000000)
        self.assertIsNone(hdr["sys_uptime"])

    def test_template_then_data(self):
        msg = p.ipfix([p.data_template(400, p.FLOW_FIELDS),
                       p.data_set(400, p.flow_payload())])
        _, records, opts = self.parse(msg)
        self.assertEqual(opts, [])
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["src_addr"], "192.168.1.10")
        self.assertEqual(records[0]["octets"], 1500)
        self.assertEqual(self.stats["templates_new"], 1)

    def test_templates_persist_across_datagrams(self):
        self.parse(p.ipfix([p.data_template(400, p.FLOW_FIELDS)]))
        _, records, _ = self.parse(p.ipfix([p.data_set(400, p.flow_payload())]))
        self.assertEqual(len(records), 1)

    def test_data_before_its_template_is_deferred_not_lost_forever(self):
        _, records, _ = self.parse(p.ipfix([p.data_set(400, p.flow_payload())]))
        self.assertEqual(records, [])
        self.assertEqual(self.stats["deferred"], 1)
        self.parse(p.ipfix([p.data_template(400, p.FLOW_FIELDS)]))
        _, records, _ = self.parse(p.ipfix([p.data_set(400, p.flow_payload())]))
        self.assertEqual(len(records), 1)
        self.assertEqual(self.stats["deferred"], 1)

    def test_several_records_in_one_set(self):
        payload = p.flow_payload() * 3
        msg = p.ipfix([p.data_template(400, p.FLOW_FIELDS),
                       p.data_set(400, payload)])
        _, records, _ = self.parse(msg)
        self.assertEqual(len(records), 3)

    def test_trailing_padding_is_not_a_record(self):
        # Sets are padded to a 4-byte boundary. Padding shorter than a record
        # must not be decoded as one.
        payload = p.flow_payload() + b"\x00\x00\x00"
        msg = p.ipfix([p.data_template(400, p.FLOW_FIELDS),
                       p.data_set(400, payload)])
        _, records, _ = self.parse(msg)
        self.assertEqual(len(records), 1)

    def test_templates_are_scoped_per_exporter(self):
        self.parse(p.ipfix([p.data_template(400, p.FLOW_FIELDS)]), "10.0.0.1")
        _, records, _ = self.parse(p.ipfix([p.data_set(400, p.flow_payload())]),
                                   "10.0.0.2")
        self.assertEqual(records, [], "another exporter's template was used")

    def test_templates_are_scoped_per_observation_domain(self):
        self.parse(p.ipfix([p.data_template(400, p.FLOW_FIELDS)], domain=0))
        _, records, _ = self.parse(
            p.ipfix([p.data_set(400, p.flow_payload())], domain=7))
        self.assertEqual(records, [])

    def test_a_changed_template_replaces_the_old_one(self):
        self.parse(p.ipfix([p.data_template(400, p.FLOW_FIELDS)]))
        self.parse(p.ipfix([p.data_template(400, [(8, 4), (12, 4)])]))
        _, records, _ = self.parse(
            p.ipfix([p.data_set(400, b"\xc0\xa8\x01\x0a\x08\x08\x08\x08")]))
        self.assertEqual(records, [{"src_addr": "192.168.1.10",
                                    "dst_addr": "8.8.8.8"}])
        self.assertEqual(self.stats["templates_new"], 2)

    def test_relearning_the_same_template_is_not_news(self):
        for _ in range(3):
            self.parse(p.ipfix([p.data_template(400, p.FLOW_FIELDS)]))
        self.assertEqual(self.stats["templates_new"], 1)

    def test_ipv6_addresses_share_the_v4_keys(self):
        fields = [(27, 16), (28, 16), (4, 1)]
        payload = (bytes.fromhex("20010db8000000000000000000000001")
                   + bytes.fromhex("20010db8000000000000000000000002")
                   + b"\x06")
        msg = p.ipfix([p.data_template(500, fields), p.data_set(500, payload)])
        _, records, _ = self.parse(msg)
        self.assertEqual(records[0]["src_addr"], "2001:db8::1")
        self.assertEqual(records[0]["dst_addr"], "2001:db8::2")

    def test_unknown_elements_are_kept_under_a_generated_name(self):
        msg = p.ipfix([p.data_template(600, [(9999, 2)]),
                       p.data_set(600, b"\x00\x2a")])
        _, records, _ = self.parse(msg)
        self.assertEqual(records[0], {"ie9999": 42})

    def test_enterprise_elements_are_kept_and_namespaced(self):
        spec = p.enterprise_spec(33, 4, 9) + struct.pack("!HH", 4, 1)
        msg = p.ipfix([p.data_template_raw(700, 2, spec),
                       p.data_set(700, b"\x00\x00\x01\x00\x06")])
        _, records, _ = self.parse(msg)
        self.assertEqual(records[0], {"e9.33": 256, "proto": 6})

    def test_variable_length_short_form(self):
        fields = [(8, 4), (82, 0xFFFF)]
        payload = b"\xc0\xa8\x01\x0a" + bytes([4]) + b"eth0"
        msg = p.ipfix([p.data_template(800, fields), p.data_set(800, payload)])
        _, records, _ = self.parse(msg)
        self.assertEqual(records[0], {"src_addr": "192.168.1.10",
                                      "if_name": "eth0"})

    def test_variable_length_long_form(self):
        text = b"x" * 300
        fields = [(83, 0xFFFF)]
        payload = bytes([255]) + struct.pack("!H", len(text)) + text
        msg = p.ipfix([p.data_template(801, fields), p.data_set(801, payload)])
        _, records, _ = self.parse(msg)
        self.assertEqual(records[0]["if_desc"], text.decode())

    def test_a_variable_length_field_running_past_the_set_stops_cleanly(self):
        fields = [(82, 0xFFFF)]
        payload = bytes([200]) + b"short"
        msg = p.ipfix([p.data_template(802, fields), p.data_set(802, payload)])
        _, records, _ = self.parse(msg)
        self.assertEqual(records, [])

    def test_the_declared_message_length_bounds_the_walk(self):
        # Bytes past the declared length are somebody else's problem, most
        # likely a coalesced datagram or a padded frame.
        good = p.data_template(400, p.FLOW_FIELDS)
        msg = p.ipfix([good], msg_len=16 + len(good))
        msg += p.data_set(400, p.flow_payload())
        _, records, _ = self.parse(msg)
        self.assertEqual(records, [])
        self.assertEqual(self.stats["deferred"], 0)

    def test_a_zero_length_set_does_not_loop_forever(self):
        msg = p.ipfix([]) + struct.pack("!HH", 256, 0)
        hdr, records, _ = self.parse(msg)
        self.assertIsNotNone(hdr)
        self.assertEqual(records, [])

    def test_a_truncated_header_yields_nothing(self):
        self.assertEqual(self.parse(b"\x00\x0a\x00\x10"), (None, [], []))

    def test_sets_below_256_that_are_not_templates_are_ignored(self):
        # 4 to 255 are reserved. Decoding one as data would be a guess.
        msg = p.ipfix([p.raw_set(200, b"\x00" * 8)])
        hdr, records, opts = self.parse(msg)
        self.assertEqual((records, opts), ([], []))
        self.assertEqual(self.stats["deferred"], 0)


class ParseV9(unittest.TestCase):
    def setUp(self):
        self.store = TemplateStore()
        self.stats = Counter()

    def parse(self, msg):
        return parse_v9_or_ipfix(msg, "10.0.0.1", self.store, self.stats)

    def test_header_fields(self):
        hdr, _, _ = self.parse(p.v9([], seq=5, domain=2))
        self.assertEqual(hdr["version"], 9)
        self.assertEqual(hdr["sequence"], 5)
        self.assertEqual(hdr["domain"], 2)
        self.assertEqual(hdr["sys_uptime"], 100000)

    def test_template_flowset_zero(self):
        msg = p.v9([p.v9_data_template(300, p.FLOW_FIELDS),
                    p.data_set(300, p.flow_payload())])
        _, records, _ = self.parse(msg)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["dst_port"], 443)

    def test_v9_has_no_variable_length_encoding(self):
        # 0xFFFF is a literal length in v9, so a record of it cannot fit and
        # nothing is decoded. It must not be read as a length prefix.
        msg = p.v9([p.v9_data_template(301, [(82, 0xFFFF)]),
                    p.data_set(301, bytes([4]) + b"eth0")])
        _, records, _ = self.parse(msg)
        self.assertEqual(records, [])

    def test_the_declared_count_does_not_bound_the_walk(self):
        # v9's count field is records, not sets, and exporters disagree about
        # whether templates count. The sets themselves are authoritative.
        msg = p.v9([p.v9_data_template(302, p.FLOW_FIELDS),
                    p.data_set(302, p.flow_payload() * 2)], count=1)
        _, records, _ = self.parse(msg)
        self.assertEqual(len(records), 2)


class MultipleTemplatesInOneSet(unittest.TestCase):
    """A template set may carry more than one template (RFC 7011 3.4.1).

    Each template declares its own field count. A parser that instead reads
    field specifications until the end of the set lets the first template
    swallow the rest, and every template behind it is lost.
    """

    def test_both_templates_are_learned(self):
        store = TemplateStore()
        stats = Counter()
        msg = p.ipfix([p.template_set([(400, p.FLOW_FIELDS),
                                       (401, [(7, 2), (11, 2)])])])
        parse_v9_or_ipfix(msg, "10.0.0.1", store, stats)
        self.assertEqual(stats["templates_new"], 2)
        self.assertIsNotNone(store.get("10.0.0.1", 0, 401)[0])

    def test_and_data_for_the_second_one_decodes(self):
        store = TemplateStore()
        msg = p.ipfix([p.template_set([(400, p.FLOW_FIELDS),
                                       (401, [(7, 2), (11, 2)])]),
                       p.data_set(401, struct.pack("!HH", 1234, 53))])
        _, records, _ = parse_v9_or_ipfix(msg, "10.0.0.1", store, Counter())
        self.assertEqual(records, [{"src_port": 1234, "dst_port": 53}])


class TemplateStoreBookkeeping(unittest.TestCase):
    def setUp(self):
        self.store = TemplateStore()

    def test_a_new_template_is_counted(self):
        self.assertTrue(self.store.put("e", 0, 400, p.FLOW_FIELDS))
        self.assertEqual(self.store.learned, 1)

    def test_relearning_an_identical_template_is_not(self):
        self.store.put("e", 0, 400, p.FLOW_FIELDS)
        self.assertFalse(self.store.put("e", 0, 400, p.FLOW_FIELDS))
        self.assertEqual(self.store.learned, 1)

    def test_a_changed_template_is_counted_again(self):
        self.store.put("e", 0, 400, p.FLOW_FIELDS)
        self.assertTrue(self.store.put("e", 0, 400, p.FLOW_FIELDS[:3]))
        self.assertEqual(self.store.learned, 2)

    def test_get_reports_the_options_flag(self):
        self.store.put("e", 0, 400, p.FLOW_FIELDS)
        self.assertEqual(self.store.get("e", 0, 400), (p.FLOW_FIELDS, False))
        self.store.put("e", 0, 401, [("x", "uint", 4)], options=True)
        self.assertTrue(self.store.get("e", 0, 401)[1])

    def test_an_unknown_template_reads_as_absent(self):
        self.assertEqual(self.store.get("e", 0, 999), (None, False))


class TemplateStoreEvents(unittest.TestCase):
    def setUp(self):
        self.store = TemplateStore()

    def test_a_new_template_raises_one(self):
        self.store.put("e", 0, 400, p.FLOW_FIELDS)
        events = self.store.take_events()
        self.assertEqual(len(events), 1)
        self.assertIsInstance(events[0], TemplateLearned)
        self.assertEqual(events[0].exporter, "e")
        self.assertEqual(events[0].domain, 0)
        self.assertEqual(events[0].template_id, 400)
        self.assertEqual(events[0].fields, p.FLOW_FIELDS)
        self.assertFalse(events[0].options)

    def test_a_new_template_has_no_previous(self):
        self.store.put("e", 0, 400, p.FLOW_FIELDS)
        self.assertIsNone(self.store.take_events()[0].previous)

    def test_taking_them_forgets_them(self):
        self.store.put("e", 0, 400, p.FLOW_FIELDS)
        self.store.take_events()
        self.assertEqual(self.store.take_events(), [])

    def test_an_identical_resend_raises_nothing(self):
        # The whole reason this is not one event per template set. Exporters
        # resend everything they hold every few minutes.
        self.store.put("e", 0, 400, p.FLOW_FIELDS)
        self.store.take_events()
        self.store.put("e", 0, 400, p.FLOW_FIELDS)
        self.assertEqual(self.store.take_events(), [])

    def test_a_changed_template_carries_what_it_replaced(self):
        self.store.put("e", 0, 400, p.FLOW_FIELDS)
        self.store.take_events()
        self.store.put("e", 0, 400, p.FLOW_FIELDS[:3])
        events = self.store.take_events()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].previous, p.FLOW_FIELDS)
        self.assertEqual(events[0].fields, p.FLOW_FIELDS[:3])

    def test_an_options_template_says_so(self):
        self.store.put("e", 0, 400, p.FLOW_FIELDS, options=True)
        self.assertTrue(self.store.take_events()[0].options)

    def test_the_same_id_from_another_exporter_is_its_own_template(self):
        self.store.put("e1", 0, 400, p.FLOW_FIELDS)
        self.store.put("e2", 0, 400, p.FLOW_FIELDS)
        events = self.store.take_events()
        self.assertEqual([e.exporter for e in events], ["e1", "e2"])
        self.assertEqual([e.previous for e in events], [None, None])

    def test_the_same_id_in_another_domain_is_its_own_template(self):
        self.store.put("e", 0, 400, p.FLOW_FIELDS)
        self.store.put("e", 7, 400, p.FLOW_FIELDS)
        self.assertEqual([e.domain for e in self.store.take_events()], [0, 7])

    def test_a_template_evicted_and_resent_is_new_again(self):
        store = TemplateStore(max_templates=1)
        store.put("e", 0, 400, p.FLOW_FIELDS)
        store.put("e", 0, 401, p.FLOW_FIELDS)      # evicts 400
        store.take_events()
        store.put("e", 0, 400, p.FLOW_FIELDS)
        events = store.take_events()
        self.assertEqual(len(events), 1)
        self.assertIsNone(events[0].previous)

    def test_the_pending_queue_has_a_ceiling(self):
        # A caller parsing without a Decoder never drains, and an exporter
        # alternating two layouts under one ID raises an event each time.
        store = TemplateStore(max_pending=4)
        for n in range(10):
            store.put("e", 0, 400, p.FLOW_FIELDS[:1 + n % 3])
        self.assertEqual(len(store._events), 4)
        self.assertEqual(store.dropped, 6)
        self.assertEqual(len(store.take_events()), 4)
        self.assertEqual(store.dropped, 6)

    def test_the_oldest_are_the_ones_dropped(self):
        store = TemplateStore(max_pending=2)
        for tid in (400, 401, 402):
            store.put("e", 0, tid, p.FLOW_FIELDS)
        self.assertEqual([e.template_id for e in store.take_events()],
                         [401, 402])


class TemplateLearnedWording(unittest.TestCase):
    def test_a_new_one_says_it_was_learned(self):
        event = TemplateLearned("e", 0, 400, p.FLOW_FIELDS, False, None)
        self.assertIn("learned template 400", str(event))
        self.assertIn("7 fields", str(event))

    def test_a_changed_one_says_it_was_redefined(self):
        event = TemplateLearned("e", 0, 400, p.FLOW_FIELDS[:1], False,
                                p.FLOW_FIELDS)
        self.assertIn("redefined template 400", str(event))
        self.assertIn("1 field,", str(event))
        self.assertIn("was 7", str(event))

    def test_an_options_one_says_which_kind_it_is(self):
        event = TemplateLearned("e", 0, 400, p.FLOW_FIELDS, True, None)
        self.assertIn("options template 400", str(event))


class RecordMinLength(unittest.TestCase):
    def test_fixed_fields_sum(self):
        self.assertEqual(parse.record_min_length([("a", "uint", 4),
                                                  ("b", "uint", 2)]), 6)

    def test_a_variable_field_costs_its_length_prefix(self):
        self.assertEqual(parse.record_min_length([("a", "string", 0xFFFF)]), 1)

    def test_an_empty_template_still_takes_a_byte(self):
        # Otherwise the record loop cannot make progress and spins.
        self.assertEqual(parse.record_min_length([]), 1)


class ParseMessageDispatch(unittest.TestCase):
    def test_v5_needs_no_store(self):
        hdr, records, _ = parse_message(p.v5_message(count=1), "10.0.0.1")
        self.assertEqual(hdr["version"], 5)
        self.assertEqual(len(records), 1)

    def test_v9_and_ipfix_are_dispatched(self):
        store = TemplateStore()
        for msg, version in ((p.v9([]), 9), (p.ipfix([]), 10)):
            hdr, _, _ = parse_message(msg, "10.0.0.1", store)
            self.assertEqual(hdr["version"], version)

    def test_an_unsupported_version_is_distinguishable_from_a_short_one(self):
        with self.assertRaises(ValueError):
            parse_message(struct.pack("!HH", 3, 0), "10.0.0.1")
        self.assertEqual(parse_message(b"\x00", "10.0.0.1"), (None, [], []))

    def test_v9_without_a_store_is_an_error_not_a_silent_nothing(self):
        with self.assertRaises(ValueError):
            parse_message(p.v9([]), "10.0.0.1")


if __name__ == "__main__":
    unittest.main()
