"""Decoding NetFlow v5, NetFlow v9 and IPFIX off the wire.

Nothing in here touches a socket, a stream, or any clock the caller cannot
control. Hand it bytes and it hands back records, which makes the same code
usable on a live datagram, on a frame lifted out of a pcap, or on a fixture in
a test.

The three entry points are :func:`parse_v5`, :func:`parse_v9_or_ipfix` and the
version-dispatching :func:`parse_message`. All three return the same shape::

    (header, flow_records, option_records)

`header` is a dict describing the export message, or None when the datagram was
too short to hold one. `flow_records` describe traffic. `option_records`
describe the exporter itself, things like sampling rates and interface names,
and are kept apart from the flows deliberately: an option record decoded into
the flow list looks like a flow with no addresses and inflates every count
downstream.
"""

import ipaddress
import struct
import time
from collections import Counter, OrderedDict
from socket import inet_ntoa

from .ie import IE

__all__ = [
    "IPFIX_HDR", "NTP_EPOCH", "UNSPECIFIED", "V5_HDR", "V5_REC", "V9_HDR",
    "SUPPORTED_VERSIONS",
    "TemplateStore", "decode_value", "flow_duration", "flow_endpoints",
    "flow_timestamp", "parse_data_record", "parse_message", "parse_v5",
    "parse_v9_or_ipfix", "read_template_fields", "record_min_length",
]

SUPPORTED_VERSIONS = (5, 9, 10)

#: Seconds between the NTP epoch (1 Jan 1900) and the UNIX epoch (1 Jan 1970).
#: IPFIX dateTimeMicroseconds and dateTimeNanoseconds are NTP timestamps rather
#: than counts since the UNIX epoch. See :func:`decode_value`.
NTP_EPOCH = 2208988800

#: Values meaning "this field was not filled in". A template carrying both the
#: IPv4 and the IPv6 spelling of one field, IE 8 and IE 27 both being src_addr,
#: sends the unused family as zeros, and those must not overwrite the family
#: that was populated. See :func:`parse_data_record`.
#:
#: Zero is in here on purpose, which costs one case: an exporter that pads the
#: unused family with 0xFF rather than with zeros wins over a legitimately zero
#: value in the populated family: a real /0 mask read as /255. That was
#: measured against the alternative. Dropping zero fixes the 0xFF exporter and
#: breaks the ordinary zero-filling one, which is the common shape on real
#: networks; and an exporter padding with 0xFF also emits 255.255.255.255 in
#: its address fields, which no rule here catches, so it is already producing
#: junk. The trade is pinned in tests/test_hardening.py.
UNSPECIFIED = frozenset((None, 0, "", "0.0.0.0", "::"))

#: How many templates one store keeps before evicting the least recently used.
#: Templates are keyed by source address, and the source address of a UDP
#: datagram is trivially forged, so an uncapped store is a memory leak anyone
#: who can reach the socket may pull on. Far above any real deployment: a
#: collector sees tens of exporters, each with a handful of domains and
#: templates.
MAX_TEMPLATES = 10000


def decode_value(raw, kind):
    """Turn raw field bytes into a Python value based on the declared kind.

    Called once per field per flow, so it is the hottest function here and the
    choice of conversion shows up in the throughput figure. inet_ntoa is an
    order of magnitude quicker than building an ipaddress object only to
    stringify it, and produces the identical dotted quad for all 2**32 inputs.
    """
    try:
        if kind == "ipv4" and len(raw) == 4:
            return inet_ntoa(raw)
        if kind == "ipv6" and len(raw) == 16:
            # Deliberately not inet_ntop. It renders IPv4-mapped and
            # IPv4-compatible addresses in their dotted-quad form, giving
            # "::ffff:192.168.1.10" where ipaddress gives "::ffff:c0a8:10a",
            # and dual-stack exporters do send those. Two spellings of one
            # address is a silent duplicate in anything that groups by string.
            return str(ipaddress.IPv6Address(raw))
        if kind == "ntp" and len(raw) == 8:
            # RFC 7011 6.1.9 and 6.1.10: dateTimeMicroseconds and
            # dateTimeNanoseconds are 64-bit NTP timestamps: seconds since
            # 1900 in the high word, a fraction in units of 1/2**32 in the low
            # one, and NOT counts since the UNIX epoch. Divide the raw word by
            # 1e6 and the flow lands in the year 540,000 with a duration 4295x
            # too long. dateTimeSeconds and dateTimeMilliseconds (IE 150-153)
            # really are plain epoch counts and are left alone.
            word = int.from_bytes(raw, "big")
            if word == 0:
                return 0        # an unset field, not midnight in 1900
            return ((word >> 32) - NTP_EPOCH) + (word & 0xFFFFFFFF) / 4294967296.0
        if kind == "mac":
            return ":".join(f"{b:02x}" for b in raw)
        if kind == "string":
            return raw.decode("utf-8", "replace").rstrip("\x00").strip()
        if kind == "uint":
            return int.from_bytes(raw, "big")
    except Exception:
        pass
    # Fall back: small buffers are almost always integers, otherwise hex.
    if 0 < len(raw) <= 8:
        return int.from_bytes(raw, "big")
    return raw.hex()


class TemplateStore:
    """Templates are scoped per exporter and per observation domain.

    Options templates live in the same key space as data templates, since an
    exporter allocates template IDs from one pool, but they describe metadata
    about the exporter rather than traffic, so which kind a template is has to
    be recorded alongside it. Without that, option data records decode into what
    looks like a flow with no addresses and get handed to the caller as one.

    An instance is not thread safe. One decoder, one store; if two threads
    decode, give each its own; templates are scoped per exporter and domain
    anyway, so nothing is shared that matters.
    """

    def __init__(self, max_templates=MAX_TEMPLATES):
        self.templates = OrderedDict()
        self.learned = 0
        self.evicted = 0
        self.max_templates = max_templates

    def put(self, exporter, domain, tid, fields, options=False):
        """Record a template. Returns True when it is new or has changed."""
        key = (exporter, domain, tid)
        old = self.templates.get(key)
        self.templates[key] = (fields, options)
        self.templates.move_to_end(key)
        while len(self.templates) > self.max_templates:
            self.templates.popitem(last=False)
            self.evicted += 1
        if old is None or old[0] != fields:
            self.learned += 1
            return True
        return False

    def get(self, exporter, domain, tid):
        """Returns (fields, is_options), or (None, False) if not learned yet."""
        key = (exporter, domain, tid)
        entry = self.templates.get(key)
        if entry is None:
            return (None, False)
        # Reading counts as use: an exporter still sending data for a template
        # must not have it evicted by a flood of addresses that never send any.
        self.templates.move_to_end(key)
        return entry

    def __len__(self):
        return len(self.templates)


V5_HDR = struct.Struct("!HHIIIIBBH")
V5_REC = struct.Struct("!4s4s4sHHIIIIHHBBBBHHBBH")
V9_HDR = struct.Struct("!HHIIII")
IPFIX_HDR = struct.Struct("!HHIII")


def parse_v5(data, exporter):
    """Returns (header, flow records, option records).

    v5 has no options templates; the sampling rate rides in the header instead.
    It is reported as a one-element option record so that callers have a single
    shape to handle across all three versions.
    """
    if len(data) < V5_HDR.size:
        return None, [], []
    (ver, count, sys_uptime, unix_secs, unix_nsecs,
     seq, eng_type, eng_id, sampling) = V5_HDR.unpack_from(data, 0)

    hdr = {
        "version": 5,
        "sys_uptime": sys_uptime,
        "unix_secs": unix_secs,
        "sequence": seq,
        "domain": eng_id,
        "exporter": exporter,
    }

    options = []
    # Top two bits select the sampling mode, the low 14 hold the interval. An
    # unsampled v5 exporter simply clears the mode, and this header arrives with
    # every datagram, so only actual sampling is worth reporting: emitting an
    # "unsampled" record each time would swamp the option-record count.
    if (sampling >> 14) and (sampling & 0x3FFF) > 1:
        options.append({"sampling_interval": sampling & 0x3FFF,
                        "sampling_algorithm": sampling >> 14})

    records = []
    off = V5_HDR.size
    for _ in range(count):
        if off + V5_REC.size > len(data):
            break
        (src, dst, nh, in_if, out_if, pkts, octets, first, last,
         sport, dport, _pad1, flags, proto, tos, src_as, dst_as,
         src_mask, dst_mask, _pad2) = V5_REC.unpack_from(data, off)
        off += V5_REC.size
        records.append({
            "src_addr": inet_ntoa(src),
            "dst_addr": inet_ntoa(dst),
            "next_hop": inet_ntoa(nh),
            "in_if": in_if, "out_if": out_if,
            "packets": pkts, "octets": octets,
            "first_switched": first, "last_switched": last,
            "src_port": sport, "dst_port": dport,
            "tcp_flags": flags, "proto": proto, "tos": tos,
            "src_as": src_as, "dst_as": dst_as,
            "src_mask": src_mask, "dst_mask": dst_mask,
        })
    return hdr, records, options


def read_template_fields(data, off, end, ipfix, count=None):
    """Read (name, kind, length) triples until `end`. Returns fields, new off.

    `count`, when given, stops after that many field specifications even if
    bytes remain before `end`. That matters for a template set carrying more
    than one template: without it the first template swallows the rest of the
    set and every template behind it is lost.

    Fewer than `count` fields come back when the set ends first. That is a
    truncated template rather than a short one, and the caller refuses to store
    it: a template missing fields decodes every later record for that ID
    wrongly.
    """
    fields = []
    while off + 4 <= end:
        if count is not None and len(fields) >= count:
            break
        eid, flen = struct.unpack_from("!HH", data, off)
        off += 4
        enterprise = None
        if ipfix and (eid & 0x8000):
            eid &= 0x7FFF
            if off + 4 > end:
                break
            enterprise = struct.unpack_from("!I", data, off)[0]
            off += 4
        name, kind = IE.get(eid, (f"ie{eid}", "auto"))
        if enterprise is not None:
            name = f"e{enterprise}.{eid}"
            kind = "auto"
        fields.append((name, kind, flen))
    return fields, off


def record_min_length(fields):
    """The fewest bytes a record of this template can occupy.

    A variable-length field costs at least its one-byte length prefix, hence
    the 1. Used to tell a remaining record from trailing set padding.
    """
    total = 0
    for _name, _kind, flen in fields:
        total += 1 if flen == 0xFFFF else flen
    return max(total, 1)


def parse_data_record(data, off, set_end, fields, ipfix, dedupe=False):
    """Decode one data record. Returns (record dict, new offset) or (None, set_end).

    `dedupe` guards the case where two information elements in one template
    normalise to the same key: IE 8 and IE 27 are both src_addr, being the IPv4
    and the IPv6 spelling of it. Exporters that emit one unified template for
    both families zero-fill the one the flow does not use, so without the guard
    the later field overwrites a real address with "::". With it, a value that
    means "not filled in" never displaces one already present. The caller sets
    it only for templates that actually repeat a name, so the common path keeps
    a plain assignment.
    """
    rec = {}
    for name, kind, flen in fields:
        length = flen
        if ipfix and flen == 0xFFFF:
            if off >= set_end:
                return None, set_end
            length = data[off]
            off += 1
            if length == 255:
                if off + 2 > set_end:
                    return None, set_end
                length = struct.unpack_from("!H", data, off)[0]
                off += 2
        if off + length > set_end:
            return None, set_end
        raw = data[off:off + length]
        off += length
        value = decode_value(raw, kind)
        if dedupe and value in UNSPECIFIED and name in rec:
            continue
        rec[name] = value
    return rec, off


def parse_v9_or_ipfix(data, exporter, store, stats=None):
    """Returns (header, flow records, option records).

    `store` is a :class:`TemplateStore` that must outlive the datagram:
    exporters resend templates only periodically, and a data set arriving
    before its template cannot be decoded at all.

    `stats` is an optional mapping, for which a ``collections.Counter`` is the
    obvious choice, into which two keys are counted: ``templates_new`` for each
    template learned or changed, and ``deferred`` for each data set dropped
    because its template has not been seen yet. Pass None to discard them.
    """
    if stats is None:
        stats = Counter()
    if len(data) < 2:
        return None, [], []
    version = struct.unpack_from("!H", data, 0)[0]
    ipfix = version == 10

    if ipfix:
        if len(data) < IPFIX_HDR.size:
            return None, [], []
        ver, msg_len, export_time, seq, domain = IPFIX_HDR.unpack_from(data, 0)
        hdr = {
            "version": 10, "unix_secs": export_time, "sequence": seq,
            "domain": domain, "exporter": exporter, "sys_uptime": None,
        }
        off = IPFIX_HDR.size
        msg_end = min(msg_len, len(data)) if msg_len else len(data)
        tmpl_set, opt_set = 2, 3
    else:
        if len(data) < V9_HDR.size:
            return None, [], []
        ver, count, sys_uptime, unix_secs, seq, domain = V9_HDR.unpack_from(data, 0)
        hdr = {
            "version": 9, "unix_secs": unix_secs, "sequence": seq,
            "domain": domain, "exporter": exporter, "sys_uptime": sys_uptime,
        }
        off = V9_HDR.size
        msg_end = len(data)
        tmpl_set, opt_set = 0, 1

    records = []
    options = []

    while off + 4 <= msg_end:
        set_id, set_len = struct.unpack_from("!HH", data, off)
        if set_len < 4:
            break
        set_end = min(off + set_len, msg_end)
        body = off + 4
        off = set_end

        if set_id == tmpl_set:
            while body + 4 <= set_end:
                tid, field_count = struct.unpack_from("!HH", data, body)
                body += 4
                if field_count == 0:
                    continue
                fields, body = read_template_fields(data, body, set_end, ipfix,
                                                    count=field_count)
                if len(fields) != field_count:
                    # The set ended mid-template. Storing what did arrive would
                    # leave a template short of the fields the exporter
                    # declared, and every later data record for that ID would
                    # then be cut into one real flow plus fabricated ones that
                    # reach the caller as genuine traffic. Nothing after a
                    # truncated template is trustworthy either.
                    break
                if store.put(exporter, hdr["domain"], tid, fields):
                    stats["templates_new"] += 1

        elif set_id == opt_set:
            # Options templates carry metadata such as the sampling rate. Store
            # them so their data sets can be walked without desyncing.
            while body + 6 <= set_end:
                if ipfix:
                    tid, field_count, _scope_count = struct.unpack_from(
                        "!HHH", data, body)
                    body += 6
                    fields, body = read_template_fields(data, body, set_end,
                                                        True, count=field_count)
                    if len(fields) != field_count:
                        break               # truncated, as for a data template
                else:
                    tid, scope_len, opt_len = struct.unpack_from("!HHH", data, body)
                    body += 6
                    # v9 declares the two halves as byte lengths, not as field
                    # counts. Both hold whole 4-byte field specifications, so a
                    # length that is not a multiple of 4 is malformed: read
                    # naively it leaves the option specs misaligned by the
                    # remainder and stores a template of nonsense. A pair that
                    # overruns the set is the truncation case again. Either way
                    # body still advances by what was declared, so the next
                    # template in the set stays reachable.
                    start = body
                    body = min(start + scope_len + opt_len, set_end)
                    if (scope_len % 4 or opt_len % 4
                            or start + scope_len + opt_len > set_end):
                        continue
                    sfields, _ = read_template_fields(
                        data, start, start + scope_len, False)
                    ofields, _ = read_template_fields(
                        data, start + scope_len, body, False)
                    fields = sfields + ofields
                if not fields:
                    break
                if store.put(exporter, hdr["domain"], tid, fields, options=True):
                    stats["templates_new"] += 1

        elif set_id >= 256:
            fields, is_options = store.get(exporter, hdr["domain"], set_id)
            if not fields:
                stats["deferred"] += 1
                continue
            min_len = record_min_length(fields)
            sink = options if is_options else records
            # Decided once for the set rather than once per record: hardly any
            # template repeats a key, and this is the hot path.
            names = [f[0] for f in fields]
            dedupe = len(set(names)) != len(names)
            while set_end - body >= min_len:
                rec, new_body = parse_data_record(data, body, set_end, fields,
                                                  ipfix, dedupe)
                if rec is None or new_body <= body:
                    break
                body = new_body
                sink.append(rec)

    return hdr, records, options


def parse_message(data, exporter, store=None, stats=None):
    """Decode one export datagram of any supported version.

    Returns (header, flow records, option records); the header is None when the
    datagram was too short to hold one.

    Raises ValueError for a version this package does not decode, so that an
    unsupported exporter and a truncated datagram stay distinguishable. Catch
    it if you would rather count them.
    """
    if len(data) < 2:
        return None, [], []
    version = struct.unpack_from("!H", data, 0)[0]
    if version == 5:
        return parse_v5(data, exporter)
    if version in (9, 10):
        if store is None:
            raise ValueError("v9 and IPFIX need a TemplateStore that outlives "
                             "the datagram")
        return parse_v9_or_ipfix(data, exporter, store, stats)
    raise ValueError("unsupported export version %d" % version)


def flow_endpoints(rec):
    """The two addresses to treat as this flow's ends.

    An exporter that reports only post-NAT addresses is still describing a real
    conversation, so those stand in when the pre-NAT fields are absent. Anything
    that asks where a flow went should ask this rather than reading `src_addr`
    directly, so that filtering, storage and aggregation all agree.
    """
    return (rec.get("src_addr") or rec.get("post_nat_src_addr"),
            rec.get("dst_addr") or rec.get("post_nat_dst_addr"))


def flow_timestamp(rec, hdr, now=None):
    """Best effort absolute start time for a flow, as a unix float.

    IPFIX absolute timestamps are preferred. Failing those, v5 and v9 report the
    flow start as milliseconds since the exporter booted, which is turned back
    into wall clock time from the header's uptime and export time. That
    reconstruction is rejected if it lands more than a day away, which is what a
    wrapped uptime counter looks like, and the export time is used instead.

    `now` overrides the current time, so that a test need not be hostage to the
    clock.
    """
    # The us and ns keys divide by 1: decode_value has already turned those
    # NTP timestamps into UNIX seconds. Only the epoch counts need scaling.
    for key, div in (("flow_start_ms", 1000.0), ("flow_start_s", 1.0),
                     ("flow_start_us", 1.0), ("flow_start_ns", 1.0)):
        val = rec.get(key)
        if val:
            return val / div

    first = rec.get("first_switched")
    uptime = hdr.get("sys_uptime")
    base = hdr.get("unix_secs")
    if now is None:
        now = time.time()
    if first is not None and uptime is not None and base:
        candidate = base - (uptime - first) / 1000.0
        # Guard against an uptime counter wrap producing nonsense.
        if abs(candidate - now) < 86400:
            return candidate
    return base or now


def flow_duration(rec, hdr=None):
    """How long the flow lasted, in seconds, or None if it cannot be told.

    `hdr` is accepted and ignored. It is here because the duration once needed
    it and callers pass it.
    """
    # As in flow_timestamp: the us and ns pairs arrive already in seconds.
    pairs = [("flow_start_ms", "flow_end_ms", 1000.0),
             ("flow_start_s", "flow_end_s", 1.0),
             ("flow_start_us", "flow_end_us", 1.0),
             ("flow_start_ns", "flow_end_ns", 1.0),
             ("first_switched", "last_switched", 1000.0)]
    for a, b, div in pairs:
        sa, sb = rec.get(a), rec.get(b)
        if sa and sb and sb >= sa:
            return (sb - sa) / div
    return None
