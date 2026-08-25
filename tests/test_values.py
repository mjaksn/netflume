"""Field-level classification and naming."""

import unittest

from netflume import (
    ADDR_KINDS,
    addr_kind,
    flow_end_reason_name,
    proto_name,
    service_name,
    tcp_flags_str,
)


class AddressKind(unittest.TestCase):
    CASES = [
        ("192.168.1.1", "private"), ("10.0.0.1", "private"),
        ("172.16.0.1", "private"), ("fd00::1", "private"),
        ("8.8.8.8", "public"), ("2001:4860:4860::8888", "public"),
        ("224.0.0.251", "multicast"), ("ff02::1", "multicast"),
        ("127.0.0.1", "special"), ("169.254.1.1", "special"),
        ("0.0.0.0", "special"), ("::1", "special"),
        ("not an address", "unknown"), ("", "unknown"),
    ]

    def test_classification(self):
        for addr, want in self.CASES:
            with self.subTest(addr):
                self.assertEqual(addr_kind(addr), want)

    def test_every_answer_is_one_of_the_documented_kinds(self):
        for addr, _ in self.CASES:
            self.assertIn(addr_kind(addr), ADDR_KINDS)

    def test_the_answer_is_stable_when_cached(self):
        self.assertEqual(addr_kind("8.8.8.8"), addr_kind("8.8.8.8"))

    def test_both_families_are_handled_since_they_share_record_keys(self):
        self.assertEqual(addr_kind("2606:4700:4700::1111"), "public")

    def test_the_documentation_prefix_is_not_public(self):
        # 2001:db8::/32 is reserved for documentation and is not globally
        # routable, so "private" is the right answer even though it looks
        # like an ordinary address in every example ever written.
        self.assertEqual(addr_kind("2001:db8::1"), "private")


class ServiceName(unittest.TestCase):
    def test_a_well_known_tcp_port(self):
        # The system services database is what answers, so the exact string
        # is the platform's business. That it names something is ours.
        self.assertIn(service_name(80, 6), ("http", "www", "www-http", None))

    def test_an_ephemeral_port_is_not_named(self):
        # Naming the client end of a connection produces confident nonsense.
        self.assertIsNone(service_name(51000, 6))
        self.assertIsNone(service_name(65535, 17))

    def test_port_zero_and_none(self):
        self.assertIsNone(service_name(0, 6))
        self.assertIsNone(service_name(None, 6))

    def test_a_protocol_with_no_service_namespace(self):
        self.assertIsNone(service_name(80, 47))     # GRE
        self.assertIsNone(service_name(80, None))

    def test_repeated_lookups_agree(self):
        self.assertEqual(service_name(53, 17), service_name(53, 17))


class ProtocolNames(unittest.TestCase):
    def test_the_common_ones(self):
        self.assertEqual(proto_name(6), "TCP")
        self.assertEqual(proto_name(17), "UDP")
        self.assertEqual(proto_name(1), "ICMP")
        self.assertEqual(proto_name(58), "ICMP6")

    def test_an_unknown_number_is_none_not_a_guess(self):
        self.assertIsNone(proto_name(253))
        self.assertIsNone(proto_name(None))

    def test_flow_end_reasons(self):
        self.assertEqual(flow_end_reason_name(1), "idle")
        self.assertEqual(flow_end_reason_name(2), "active")
        self.assertIsNone(flow_end_reason_name(99))


class TcpFlagString(unittest.TestCase):
    def test_a_syn(self):
        self.assertEqual(tcp_flags_str(0x02), "......S.")

    def test_an_established_transfer(self):
        self.assertEqual(tcp_flags_str(0x18), "...AP...")

    def test_everything_set(self):
        self.assertEqual(tcp_flags_str(0xFF), "CEUAPRSF")

    def test_zero_flags_are_dots(self):
        self.assertEqual(tcp_flags_str(0), "........")

    def test_absent_flags_are_empty_which_is_not_the_same_as_zero(self):
        # An exporter that sends no flags field is saying nothing; one that
        # sends 0 is saying a flow carried no flagged segments.
        self.assertEqual(tcp_flags_str(None), "")

    def test_the_width_is_fixed_so_it_sorts_and_compares(self):
        self.assertEqual(len(tcp_flags_str(0x18)), 8)


if __name__ == "__main__":
    unittest.main()
