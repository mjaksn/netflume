"""Synthetic export messages, built by hand.

There is no real NetFlow exporter in the loop anywhere in this suite, so every
byte tested is one of these. The builders are deliberately low level and were
written from the RFCs; that reading of the specifications is the only reason to
believe they are shaped right.

Kept deliberately dumb: no validation, no convenience defaults that hide the
field being tested. A builder that quietly fixes a malformed message is no use
for testing what happens to malformed messages.
"""

import struct

V5_HDR = struct.Struct("!HHIIIIBBH")
V5_REC = struct.Struct("!4s4s4sHHIIIIHHBBBBHHBBH")


# == IPFIX and v9 ============================================================

def ipfix(sets, seq=0, domain=0, export_time=1700000000, msg_len=None):
    """An IPFIX message. `msg_len` overrides the declared length, for testing
    what happens when it disagrees with the datagram."""
    body = b"".join(sets)
    declared = 16 + len(body) if msg_len is None else msg_len
    return struct.pack("!HHIII", 10, declared, export_time, seq, domain) + body


def v9(sets, count=1, seq=0, domain=0, uptime=100000, unix_secs=1700000000):
    body = b"".join(sets)
    return (struct.pack("!HHIIII", 9, count, uptime, unix_secs, seq, domain)
            + body)


def field_specs(fields):
    """(element id, length) pairs as wire field specifications."""
    return b"".join(struct.pack("!HH", eid, length) for eid, length in fields)


def enterprise_spec(eid, length, pen):
    """One enterprise-specific field specification: high bit set, PEN after."""
    return struct.pack("!HHI", eid | 0x8000, length, pen)


def data_template(tid, fields):
    """An IPFIX/v9 data template set holding one template."""
    body = struct.pack("!HH", tid, len(fields)) + field_specs(fields)
    return struct.pack("!HH", 2, 4 + len(body)) + body


def data_template_raw(tid, field_count, spec_bytes):
    """A template set whose declared field count and bytes need not agree."""
    body = struct.pack("!HH", tid, field_count) + spec_bytes
    return struct.pack("!HH", 2, 4 + len(body)) + body


def template_set(templates):
    """One template SET carrying several templates, which RFC 7011 3.4.1
    allows and which naive parsers mishandle. Each entry is (tid, fields)."""
    body = b"".join(struct.pack("!HH", tid, len(fields)) + field_specs(fields)
                    for tid, fields in templates)
    return struct.pack("!HH", 2, 4 + len(body)) + body


def v9_data_template(tid, fields):
    """v9 puts data templates in FlowSet 0, not set 2."""
    body = struct.pack("!HH", tid, len(fields)) + field_specs(fields)
    return struct.pack("!HH", 0, 4 + len(body)) + body


def ipfix_options_template(tid, scope, opts):
    """IPFIX options template. The declared field count covers scope + options."""
    body = struct.pack("!HHH", tid, len(scope) + len(opts), len(scope))
    body += field_specs(scope) + field_specs(opts)
    return struct.pack("!HH", 3, 4 + len(body)) + body


def v9_options_template(tid, scope, opts):
    """v9 options template. Lengths are in bytes, not field counts."""
    body = struct.pack("!HHH", tid, 4 * len(scope), 4 * len(opts))
    body += field_specs(scope) + field_specs(opts)
    return struct.pack("!HH", 1, 4 + len(body)) + body


def data_set(tid, payload):
    return struct.pack("!HH", tid, 4 + len(payload)) + payload


def raw_set(set_id, payload):
    """A set with an arbitrary id, for exercising set dispatch."""
    return struct.pack("!HH", set_id, 4 + len(payload)) + payload


# == the flow template used throughout =======================================

#: srcAddr, dstAddr, srcPort, dstPort, protocol, octets, packets
FLOW_FIELDS = [(8, 4), (12, 4), (7, 2), (11, 2), (4, 1), (1, 4), (2, 4)]


def flow_payload(src=b"\xc0\xa8\x01\x0a", dst=b"\x08\x08\x08\x08",
                 sport=51000, dport=443, proto=6, octets=1500, packets=12):
    return (src + dst + struct.pack("!HH", sport, dport) + bytes([proto])
            + struct.pack("!II", octets, packets))


#: The same flow with IPFIX absolute timestamps, so tests need not mock a clock.
TIMED_FLOW_FIELDS = FLOW_FIELDS + [(152, 8), (153, 8)]


def timed_flow_payload(start_ms=1700000000000, end_ms=1700000012500, **kw):
    return flow_payload(**kw) + struct.pack("!QQ", start_ms, end_ms)


#: octetDeltaCount is IE 1, but plenty of exporters send IE 85 instead.
TOTALS_FLOW_FIELDS = [(8, 4), (12, 4), (4, 1), (85, 8), (86, 8)]


def totals_flow_payload(src=b"\xc0\xa8\x01\x0a", dst=b"\x08\x08\x08\x08",
                        proto=6, octets=4096, packets=9):
    return src + dst + bytes([proto]) + struct.pack("!QQ", octets, packets)


# == NetFlow v5 ==============================================================

def v5(count=0, sampling_word=0, seq=0, uptime=100000, unix_secs=1700000000,
       engine_id=0, records=()):
    """A v5 datagram. `count` is declared independently of `records` so that a
    message can claim more records than it carries."""
    pkt = V5_HDR.pack(5, count, uptime, unix_secs, 0, seq, 0, engine_id,
                      sampling_word)
    return pkt + b"".join(records)


def v5_record(src=(192, 168, 1, 10), dst=(8, 8, 8, 8), next_hop=(192, 168, 1, 1),
              in_if=1, out_if=2, packets=12, octets=1500, first=90000,
              last=100000, sport=51000, dport=443, flags=0x18, proto=6, tos=0,
              src_as=0, dst_as=0, src_mask=24, dst_mask=24):
    return V5_REC.pack(bytes(src), bytes(dst), bytes(next_hop), in_if, out_if,
                       packets, octets, first, last, sport, dport, 0, flags,
                       proto, tos, src_as, dst_as, src_mask, dst_mask, 0)


def v5_message(seq=0, count=3, unix_secs=1700000000, uptime=100000,
               sampling_word=0):
    """A v5 datagram carrying `count` flows, each to a different source."""
    records = [v5_record(src=(192, 168, 1, 10 + i), sport=51000 + i)
               for i in range(count)]
    return v5(count=count, sampling_word=sampling_word, seq=seq, uptime=uptime,
              unix_secs=unix_secs, records=records)
