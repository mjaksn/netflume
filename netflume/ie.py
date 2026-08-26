"""Information element definitions.

Maps NetFlow v9 and IPFIX element IDs to (normalised name, value kind). The
names are deliberately normalised so v5, v9 and IPFIX all land in the same
dictionary keys: a consumer writes one schema, not three.

The table is data, not logic. Adding an element is a line here, and elements
this table does not know are still decoded and still delivered, under
``ie<id>`` for a standard element and ``e<pen>.<id>`` for an enterprise one,
so an unrecognised field is never a lost field.
"""

__all__ = ["FLOW_END_REASON", "IE", "PROTO_NAMES", "TCP_FLAG_BITS"]

IE = {
    1: ("octets", "uint"),
    2: ("packets", "uint"),
    3: ("flows", "uint"),
    4: ("proto", "uint"),
    5: ("tos", "uint"),
    6: ("tcp_flags", "uint"),
    7: ("src_port", "uint"),
    8: ("src_addr", "ipv4"),
    9: ("src_mask", "uint"),
    10: ("in_if", "uint"),
    11: ("dst_port", "uint"),
    12: ("dst_addr", "ipv4"),
    13: ("dst_mask", "uint"),
    14: ("out_if", "uint"),
    15: ("next_hop", "ipv4"),
    16: ("src_as", "uint"),
    17: ("dst_as", "uint"),
    21: ("last_switched", "uint"),
    22: ("first_switched", "uint"),
    23: ("out_octets", "uint"),
    24: ("out_packets", "uint"),
    27: ("src_addr", "ipv6"),
    28: ("dst_addr", "ipv6"),
    29: ("src_mask", "uint"),
    30: ("dst_mask", "uint"),
    31: ("flow_label", "uint"),
    32: ("icmp_type_code", "uint"),
    34: ("sampling_interval", "uint"),
    35: ("sampling_algorithm", "uint"),
    36: ("active_timeout", "uint"),
    37: ("idle_timeout", "uint"),
    40: ("exported_octets", "uint"),
    41: ("exported_packets", "uint"),
    42: ("exported_flows", "uint"),
    48: ("sampler_id", "uint"),
    49: ("sampler_mode", "uint"),
    50: ("sampler_interval", "uint"),
    52: ("min_ttl", "uint"),
    53: ("max_ttl", "uint"),
    55: ("dst_tos", "uint"),
    56: ("src_mac", "mac"),
    57: ("post_dst_mac", "mac"),
    58: ("vlan", "uint"),
    59: ("post_vlan", "uint"),
    60: ("ip_version", "uint"),
    61: ("direction", "uint"),
    62: ("next_hop", "ipv6"),
    70: ("mpls_label_1", "uint"),
    80: ("dst_mac", "mac"),
    81: ("post_src_mac", "mac"),
    82: ("if_name", "string"),
    83: ("if_desc", "string"),
    84: ("sampler_name", "string"),
    85: ("octets_total", "uint"),
    86: ("packets_total", "uint"),
    89: ("forwarding_status", "uint"),
    128: ("bgp_next_as", "uint"),
    136: ("flow_end_reason", "uint"),
    138: ("observation_point_id", "uint"),
    139: ("icmp_type_code_v6", "uint"),
    145: ("template_id", "uint"),
    148: ("flow_id", "uint"),
    150: ("flow_start_s", "uint"),
    151: ("flow_end_s", "uint"),
    152: ("flow_start_ms", "uint"),
    153: ("flow_end_ms", "uint"),
    # RFC 7011 6.1.9/6.1.10. These four are NTP timestamps on the wire, not
    # counts since the UNIX epoch the way IE 150-153 are, so they decode with
    # the "ntp" kind. The key names describe the precision the information
    # element declares; the value under them is UNIX seconds as a float, the
    # same currency flow_timestamp deals in. Do not "correct" these back to
    # "uint": that reads a 1900-based timestamp as microseconds and puts every
    # flow in the year 540,000.
    154: ("flow_start_us", "ntp"),
    155: ("flow_end_us", "ntp"),
    156: ("flow_start_ns", "ntp"),
    157: ("flow_end_ns", "ntp"),
    176: ("icmp_type", "uint"),
    177: ("icmp_code", "uint"),
    178: ("icmp_type", "uint"),
    179: ("icmp_code", "uint"),
    225: ("post_nat_src_addr", "ipv4"),
    226: ("post_nat_dst_addr", "ipv4"),
    227: ("post_nat_src_port", "uint"),
    228: ("post_nat_dst_port", "uint"),
    234: ("ingress_vrf", "uint"),
    235: ("egress_vrf", "uint"),
    243: ("dot1q_vlan", "uint"),
    244: ("dot1q_prio", "uint"),
    245: ("dot1q_cust_vlan", "uint"),
    302: ("selector_id", "uint"),
    304: ("selector_algorithm", "uint"),
    305: ("sampling_packet_interval", "uint"),
    306: ("sampling_packet_space", "uint"),
    309: ("sampling_size", "uint"),
    310: ("sampling_population", "uint"),
    323: ("observation_time_ms", "uint"),
    346: ("enterprise_id", "uint"),
    351: ("srh_flags", "uint"),
}

PROTO_NAMES = {
    1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 41: "IPv6", 47: "GRE",
    50: "ESP", 51: "AH", 58: "ICMP6", 89: "OSPF", 103: "PIM", 132: "SCTP",
}

FLOW_END_REASON = {
    1: "idle", 2: "active", 3: "eof", 4: "forced", 5: "lack-of-res",
}

TCP_FLAG_BITS = [
    (0x80, "C"),  # CWR
    (0x40, "E"),  # ECE
    (0x20, "U"),  # URG
    (0x10, "A"),  # ACK
    (0x08, "P"),  # PSH
    (0x04, "R"),  # RST
    (0x02, "S"),  # SYN
    (0x01, "F"),  # FIN
]
