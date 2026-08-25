"""The typed view must agree with the dict it wraps, and lose nothing.

Every case here is driven off the synthetic messages in `tests/packets.py`,
decoded through the real parser rather than from hand-written dicts: a typed
layer tested against invented input proves only that the invention was
consistent.
"""

import dataclasses
import json
import struct
import unittest
from collections import Counter

from netflume import MODELLED_FIELDS, Flow, TemplateStore, parse_v5, parse_v9_or_ipfix

from . import packets as p


def decode(msg, exporter="10.0.0.1", store=None):
    """(header, flow records) for one IPFIX or v9 message."""
    store = store if store is not None else TemplateStore()
    hdr, records, _ = parse_v9_or_ipfix(msg, exporter, store, Counter())
    return hdr, records


def one_flow(fields, payload, **kw):
    """A Flow built from a one-record IPFIX message with the given template."""
    msg = p.ipfix([p.data_template(400, fields), p.data_set(400, payload)])
    hdr, records = decode(msg)
    return Flow.from_record(records[0], hdr, **kw)


class TheModelledFields(unittest.TestCase):
    def setUp(self):
        self.flow = one_flow(p.FLOW_FIELDS, p.flow_payload())

    def test_identity_comes_from_the_header(self):
        self.assertEqual(self.flow.exporter, "10.0.0.1")
        self.assertEqual(self.flow.version, 10)
        self.assertEqual(self.flow.domain, 0)

    def test_the_five_tuple(self):
        self.assertEqual(self.flow.src_addr, "192.168.1.10")
        self.assertEqual(self.flow.dst_addr, "8.8.8.8")
        self.assertEqual(self.flow.src_port, 51000)
        self.assertEqual(self.flow.dst_port, 443)
        self.assertEqual(self.flow.proto, 6)

    def test_the_counts(self):
        self.assertEqual(self.flow.octets, 1500)
        self.assertEqual(self.flow.packets, 12)

    def test_it_agrees_with_the_dict_it_wraps(self):
        for name in ("src_addr", "dst_addr", "src_port", "dst_port", "proto",
                     "octets", "packets"):
            self.assertEqual(getattr(self.flow, name), self.flow.raw[name])

    def test_the_modelled_field_list_is_all_readable(self):
        for name in MODELLED_FIELDS:
            getattr(self.flow, name)


class AbsentIsNotZero(unittest.TestCase):
    """A flow with no byte count is not a flow that carried nothing."""

    def setUp(self):
        # A template with nothing but addresses: everything else is genuinely
        # missing, which is what a sparse exporter produces.
        self.flow = one_flow([(8, 4), (12, 4)],
                             b"\xc0\xa8\x01\x0a\x08\x08\x08\x08")

    def test_missing_counts_are_none(self):
        self.assertIsNone(self.flow.octets)
        self.assertIsNone(self.flow.packets)

    def test_missing_ports_and_protocol_are_none(self):
        self.assertIsNone(self.flow.src_port)
        self.assertIsNone(self.flow.dst_port)
        self.assertIsNone(self.flow.proto)

    def test_a_flow_with_no_usable_times_has_no_duration(self):
        self.assertIsNone(self.flow.duration)
        self.assertIsNone(self.flow.end)

    def test_scaling_a_missing_count_leaves_it_missing(self):
        self.assertIsNone(self.flow.scaled(self.flow.octets))

    def test_flags_of_an_exporter_that_sent_none_are_empty_not_dots(self):
        self.assertIsNone(self.flow.tcp_flags)
        self.assertEqual(self.flow.flags, "")

    def test_a_real_zero_is_kept_as_zero(self):
        flow = one_flow(p.FLOW_FIELDS, p.flow_payload(octets=0, packets=0))
        self.assertEqual(flow.octets, 0)
        self.assertIsNotNone(flow.octets)


class TheAliasesThatBite(unittest.TestCase):
    def test_octets_total_stands_in_for_octets(self):
        # IE 85 rather than IE 1. A reader that looks only at IE 1 reads
        # rec["octets"] alone and counted every such exporter as zero bytes.
        flow = one_flow(p.TOTALS_FLOW_FIELDS, p.totals_flow_payload())
        self.assertEqual(flow.octets, 4096)
        self.assertEqual(flow.packets, 9)
        self.assertNotIn("octets", flow.raw)
        self.assertEqual(flow.raw["octets_total"], 4096)

    def test_the_delta_form_wins_when_somehow_both_are_present(self):
        rec = {"octets": 10, "octets_total": 999,
               "packets": 1, "packets_total": 99}
        flow = Flow.from_record(rec, {"exporter": "e", "version": 10,
                                      "domain": 0, "unix_secs": 1700000000})
        self.assertEqual((flow.octets, flow.packets), (10, 1))

    def test_post_nat_addresses_stand_in_for_absent_ones(self):
        rec = {"post_nat_src_addr": "192.168.1.10",
               "post_nat_dst_addr": "8.8.8.8"}
        flow = Flow.from_record(rec, {"exporter": "e", "version": 10,
                                      "domain": 0, "unix_secs": 1700000000})
        self.assertEqual(flow.endpoints, ("192.168.1.10", "8.8.8.8"))

    def test_pre_nat_addresses_win_when_both_are_present(self):
        rec = {"src_addr": "192.168.1.10", "dst_addr": "8.8.8.8",
               "post_nat_src_addr": "203.0.113.9",
               "post_nat_dst_addr": "203.0.113.10"}
        flow = Flow.from_record(rec, {"exporter": "e", "version": 10,
                                      "domain": 0, "unix_secs": 1700000000})
        self.assertEqual(flow.endpoints, ("192.168.1.10", "8.8.8.8"))

    def test_a_flow_with_neither_has_no_ends(self):
        flow = Flow.from_record({"proto": 6}, {"exporter": "e", "version": 10,
                                               "domain": 0,
                                               "unix_secs": 1700000000})
        self.assertEqual(flow.endpoints, (None, None))
        self.assertEqual(flow.src_kind, "unknown")

    def test_v4_and_v6_share_one_pair_of_keys(self):
        fields = [(27, 16), (28, 16)]
        payload = (bytes.fromhex("20010db8000000000000000000000001")
                   + bytes.fromhex("fe800000000000000000000000000001"))
        flow = one_flow(fields, payload)
        self.assertEqual(flow.src_addr, "2001:db8::1")
        self.assertEqual(flow.dst_kind, "special")     # link-local


class Timestamps(unittest.TestCase):
    def test_absolute_ipfix_times_are_preferred(self):
        flow = one_flow(p.TIMED_FLOW_FIELDS, p.timed_flow_payload())
        self.assertEqual(flow.start, 1700000000.0)
        self.assertEqual(flow.duration, 12.5)
        self.assertEqual(flow.end, 1700000012.5)

    def test_v5_start_is_rebuilt_from_the_header_uptime(self):
        # The record alone cannot say when this happened: first_switched is
        # milliseconds since the exporter booted. Hence Flow needs the header.
        hdr, records, _ = parse_v5(p.v5_message(count=1, unix_secs=1700000000,
                                                uptime=100000), "10.0.0.1")
        flow = Flow.from_record(records[0], hdr, now=1700000000)
        self.assertEqual(flow.start, 1700000000 - 10.0)
        self.assertEqual(flow.duration, 10.0)

    def test_a_wrapped_uptime_counter_falls_back_to_the_export_time(self):
        # 49.7 days of milliseconds is all a 32-bit counter holds. Rebuilding
        # across the wrap gives a time weeks away; the export time is better.
        hdr, records, _ = parse_v5(p.v5_message(count=1, unix_secs=1700000000,
                                                uptime=4000000000), "10.0.0.1")
        flow = Flow.from_record(records[0], hdr, now=1700000000)
        self.assertEqual(flow.start, 1700000000)

    def test_started_at_is_an_aware_utc_datetime(self):
        flow = one_flow(p.TIMED_FLOW_FIELDS, p.timed_flow_payload())
        when = flow.started_at()
        self.assertIsNotNone(when.tzinfo)
        self.assertEqual(when.year, 2023)

    def test_start_is_never_none_even_with_nothing_to_go_on(self):
        flow = one_flow([(8, 4)], b"\xc0\xa8\x01\x0a")
        self.assertEqual(flow.start, 1700000000)       # the export time


class DerivedProperties(unittest.TestCase):
    def setUp(self):
        self.flow = one_flow(p.FLOW_FIELDS, p.flow_payload())

    def test_address_classification(self):
        self.assertEqual(self.flow.src_kind, "private")
        self.assertEqual(self.flow.dst_kind, "public")

    def test_external_means_one_end_local_and_one_not(self):
        self.assertTrue(self.flow.is_external)

    def test_purely_local_traffic_is_not_external(self):
        flow = one_flow(p.FLOW_FIELDS,
                        p.flow_payload(dst=b"\xc0\xa8\x01\x0b"))
        self.assertFalse(flow.is_external)

    def test_transit_traffic_is_not_external_either(self):
        flow = one_flow(p.FLOW_FIELDS,
                        p.flow_payload(src=b"\x01\x01\x01\x01"))
        self.assertFalse(flow.is_external)

    def test_the_protocol_gets_a_name(self):
        self.assertEqual(self.flow.proto_name, "TCP")

    def test_an_unnamed_protocol_is_none_not_a_guess(self):
        flow = one_flow(p.FLOW_FIELDS, p.flow_payload(proto=253))
        self.assertIsNone(flow.proto_name)

    def test_the_service_reads_the_destination_only(self):
        # The source port of a client connection is ephemeral; naming it
        # produces nonsense such as calling every web request "sip".
        self.assertIn(self.flow.service, ("https", None))
        flow = one_flow(p.FLOW_FIELDS, p.flow_payload(sport=443, dport=51000))
        self.assertIsNone(flow.service)

    def test_flags_render_as_a_fixed_width_string(self):
        flow = one_flow(p.FLOW_FIELDS + [(6, 1)],
                        p.flow_payload() + bytes([0x18]))
        self.assertEqual(flow.flags, "...AP...")

    def test_sampling_scales_the_counts_back_up(self):
        flow = one_flow(p.FLOW_FIELDS, p.flow_payload(), sampling_rate=1000)
        self.assertEqual(flow.octets, 1500, "the raw count is left alone")
        self.assertEqual(flow.scaled(flow.octets), 1500000)

    def test_the_default_rate_is_one_so_scaling_is_a_no_op(self):
        self.assertEqual(self.flow.sampling_rate, 1)
        self.assertEqual(self.flow.scaled(self.flow.octets), 1500)


class NothingIsLost(unittest.TestCase):
    def test_an_unknown_element_reaches_the_consumer(self):
        flow = one_flow([(8, 4), (9999, 2)], b"\xc0\xa8\x01\x0a\x00\x2a")
        self.assertEqual(flow.get("ie9999"), 42)
        self.assertIn("ie9999", flow)

    def test_an_enterprise_element_reaches_the_consumer(self):
        spec = p.enterprise_spec(33, 4, 9) + struct.pack("!HH", 8, 4)
        msg = p.ipfix([p.data_template_raw(700, 2, spec),
                       p.data_set(700, b"\x00\x00\x01\x00\xc0\xa8\x01\x0a")])
        hdr, records = decode(msg)
        flow = Flow.from_record(records[0], hdr)
        self.assertEqual(flow.get("e9.33"), 256)
        self.assertEqual(flow.src_addr, "192.168.1.10")

    def test_get_of_something_absent_returns_the_default(self):
        flow = one_flow(p.FLOW_FIELDS, p.flow_payload())
        self.assertIsNone(flow.get("nonesuch"))
        self.assertEqual(flow.get("nonesuch", 0), 0)

    def test_raw_is_the_parser_dict_itself_not_a_copy(self):
        hdr, records = decode(p.ipfix([p.data_template(400, p.FLOW_FIELDS),
                                       p.data_set(400, p.flow_payload())]))
        flow = Flow.from_record(records[0], hdr)
        self.assertIs(flow.raw, records[0])


class Serialisation(unittest.TestCase):
    def setUp(self):
        self.flow = one_flow(p.TIMED_FLOW_FIELDS, p.timed_flow_payload())

    def test_as_dict_carries_every_decoded_field(self):
        out = self.flow.as_dict()
        for key, value in self.flow.raw.items():
            self.assertEqual(out[key], value)

    def test_and_the_metadata_keys(self):
        out = self.flow.as_dict()
        self.assertEqual(out["_exporter"], "10.0.0.1")
        self.assertEqual(out["_version"], 10)
        self.assertEqual(out["_timestamp"], 1700000000.0)
        self.assertEqual(out["_domain"], 0)
        self.assertEqual(out["_duration"], 12.5)
        self.assertEqual(out["_sampling_rate"], 1)

    def test_it_survives_json_without_a_custom_encoder(self):
        # as_dict() promises JSON-safe values, so no default= is needed.
        text = json.dumps(self.flow.as_dict())
        self.assertEqual(json.loads(text)["dst_addr"], "8.8.8.8")

    def test_the_row_form_is_a_fixed_column_set(self):
        row = self.flow.as_dict(include_raw=False)
        self.assertEqual(tuple(row), MODELLED_FIELDS)

    def test_the_row_form_gains_no_columns_from_an_odd_exporter(self):
        # A database table must not need a migration because someone plugged
        # in a router that sends a vendor element.
        odd = one_flow([(8, 4), (9999, 2)], b"\xc0\xa8\x01\x0a\x00\x2a")
        self.assertEqual(tuple(odd.as_dict(include_raw=False)), MODELLED_FIELDS)

    def test_timestamps_leave_as_epoch_floats(self):
        row = self.flow.as_dict(include_raw=False)
        self.assertIsInstance(row["start"], float)

    def test_json_survives_a_field_that_is_not_natively_serialisable(self):
        flow = Flow.from_record({"weird": b"\x00\x01"},
                                {"exporter": "e", "version": 10, "domain": 0,
                                 "unix_secs": 1700000000})
        json.dumps(flow.as_dict())


class Construction(unittest.TestCase):
    def test_a_flow_is_frozen(self):
        flow = one_flow(p.FLOW_FIELDS, p.flow_payload())
        with self.assertRaises(dataclasses.FrozenInstanceError):
            flow.octets = 1

    def test_flows_of_equal_content_compare_equal(self):
        a = one_flow(p.FLOW_FIELDS, p.flow_payload())
        b = one_flow(p.FLOW_FIELDS, p.flow_payload())
        self.assertEqual(a, b)

    def test_it_prints_as_something_readable(self):
        flow = one_flow(p.FLOW_FIELDS, p.flow_payload())
        self.assertEqual(str(flow),
                         "TCP 192.168.1.10:51000 -> 8.8.8.8:443 1500 bytes")

    def test_every_version_produces_the_same_type(self):
        # One class, a version field, and no per-protocol subclasses: the wire
        # formats differ but the normalised record deliberately does not.
        v5_hdr, v5_records, _ = parse_v5(p.v5_message(count=1), "10.0.0.1")
        v5_flow = Flow.from_record(v5_records[0], v5_hdr, now=1700000000)
        v9_hdr, v9_records = decode(
            p.v9([p.v9_data_template(300, p.FLOW_FIELDS),
                  p.data_set(300, p.flow_payload())]))
        v9_flow = Flow.from_record(v9_records[0], v9_hdr)
        ipfix_flow = one_flow(p.FLOW_FIELDS, p.flow_payload())

        self.assertEqual({type(f) for f in (v5_flow, v9_flow, ipfix_flow)},
                         {Flow})
        self.assertEqual([f.version for f in (v5_flow, v9_flow, ipfix_flow)],
                         [5, 9, 10])
        for flow in (v5_flow, v9_flow, ipfix_flow):
            self.assertEqual(flow.dst_addr, "8.8.8.8")
            self.assertEqual(flow.dst_port, 443)
            self.assertEqual(flow.octets, 1500)


if __name__ == "__main__":
    unittest.main()
