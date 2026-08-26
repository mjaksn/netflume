# netflume

[![CI](https://github.com/mjaksn/netflume/actions/workflows/ci.yml/badge.svg)](https://github.com/mjaksn/netflume/actions/workflows/ci.yml)
[![Release](https://github.com/mjaksn/netflume/actions/workflows/release.yml/badge.svg)](https://github.com/mjaksn/netflume/actions/workflows/release.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/mjaksn/netflume/blob/main/LICENSE)

NetFlow v5, NetFlow v9 and IPFIX collection and parsing, as a library. Standard
library only, no dependencies, Python 3.9 and up.

```python
from netflume import Collector

with Collector(port=2055) as collector:
    for flow in collector.flows():
        print(flow.src_addr, "->", flow.dst_addr, flow.octets, "bytes")
```

`netflume` decodes the three protocols a router is likely to speak, tracks the
templates v9 and IPFIX need in order to be decodable at all, and surfaces the
two things an exporter says about itself that change what its numbers mean: the
sampling rate, and gaps in the export sequence. It does not render, aggregate,
store or alert. Those are the caller's business, and keeping them out is what
makes the same package usable by a database writer, a message-bus forwarder and
an offline analyser without any of them fighting the others.

Three things are optimised for, in this order when they conflict:

**Performance.** A busy edge router emits tens of thousands of flows a second,
and a collector that falls behind loses data silently, because UDP has no
retransmission. Decoding is allocation-conscious, the typed layer is opt-in
rather than mandatory, and the counters needed to *prove* nothing was lost are
maintained as part of normal operation rather than bolted on.

**Versatility.** The parser is separable from the socket: feed it from a
capture, a queue or a test fixture. The socket layer offers a blocking
iterator, a bounded poll and a raw `fileno()`, so it fits a thread, a loop of
your own design, or a `selectors` reactor without adapters.

**Ease of use.** One import, four lines to a working collector. Field aliases
that differ between exporters are resolved in one place instead of at every
call site. Every diagnostic is an object you can branch on, and also a log
record if that is all you want.

---

## Contents

- [Installing](#installing)
- [The two layers](#the-two-layers)
- [Collector](#collector)
- [Decoder and Message](#decoder-and-message)
- [The flow shape](#the-flow-shape)
- [Flow, the typed view](#flow-the-typed-view)
- [Events](#events)
- [Sampling](#sampling)
- [Export gaps](#export-gaps)
- [Counters](#counters)
- [Ceilings](#ceilings)
- [Logging](#logging)
- [Hostname resolution](#hostname-resolution)
- [Parsing without a socket](#parsing-without-a-socket)
- [Sketch: logging flows to a database](#sketch-logging-flows-to-a-database)
- [Sketch: forwarding a subset over MQTT](#sketch-forwarding-a-subset-over-mqtt)
- [Protocol support](#protocol-support)
- [Tests](#tests)
- [Limitations](#limitations)
- [Everything else exported](#everything-else-exported)
- [Roadmap](#roadmap)

---

## Installing

```bash
pip install netflume
```

Or from a checkout with `pip install .`, or by copying the `netflume/` directory
next to your code. There are no dependencies to resolve either way.

```python
import netflume
netflume.__version__          # "0.2.0"
```

---

## The two layers

**Parsing** turns bytes into records. No socket, no threads, no clock the
caller cannot control. Feed it from a pcap, a queue, or a test fixture.

**Collection** binds a UDP socket and hands you what arrives.

Either works without the other. If you already have datagrams from somewhere,
skip to [Parsing without a socket](#parsing-without-a-socket).

---

## Collector

```python
Collector(port=2055, bind="0.0.0.0", decoder=None, timeout=1.0,
          rcvbuf=4*1024*1024, reuse_address=True, sock=None)
```

The socket is bound in the constructor, so a port already in use raises
`OSError` there rather than at first read. Use `with`, or call `close()`.

| | |
| --- | --- |
| `port`, `bind` | where to listen. Name an interface if only one faces the exporters. |
| `decoder` | an existing [`Decoder`](#decoder-and-message), to share template state or turn tracking off. |
| `timeout` | how long the blocking reads inside iteration wait before coming up for air. Bounds how quickly `stop()` is noticed; it is not a deadline on receiving. |
| `rcvbuf` | kernel receive buffer to request. None leaves the system default. |
| `reuse_address` | set `SO_REUSEADDR` before binding, default `True`. A restart takes the port back immediately rather than waiting for the old socket. On UDP it also lets a **second process bind the same port**, after which only one of them receives, so if a bound collector sees no traffic, suspect this first. `False` makes the clash raise `OSError` at construction instead. |
| `sock` | an already-bound socket to use instead of making one. |

### Three ways to read it

```text
for rec, hdr in collector:            plain dicts, the cheapest form
for flow in collector.flows():        typed, built on demand
for message in collector.messages():  one per datagram
message = collector.poll(timeout=0)   one datagram, or None
```

`__iter__` yields `(record, header)` rather than a bare record because a v5 or
v9 record **cannot be timestamped without its header**. The flow start is
milliseconds since the exporter booted, and turning that into a wall clock time
needs the header's uptime and export time.

All three iterators are endless: a collector with nothing to report is a quiet
network, not a finished job. Break out of the loop, or call `stop()`.

### Fitting into an existing event loop

`Collector` has a `fileno()`, so it goes straight into `selectors` or
`asyncio.loop.add_reader`. Pair it with `poll(timeout=0)`, which never blocks.

```python
import selectors

sel = selectors.DefaultSelector()
sel.register(collector, selectors.EVENT_READ)

while True:
    for key, _ in sel.select(timeout=1.0):
        message = collector.poll(timeout=0)
        if message is not None:
            handle(message)
```

`poll` returns None both when nothing arrived and when what arrived would not
decode. Neither is an error; read `collector.decoder.take_events()` if you want
to know which.

### Shutting down

```python
import signal
signal.signal(signal.SIGTERM, lambda *_: collector.stop())
```

`stop()` is safe from a signal handler or another thread and returns
immediately; the iterators finish within one `timeout`. It leaves the socket
open, so a stopped collector can still be `poll`ed. `close()` releases it and
is implied by leaving a `with` block.

| method | |
| --- | --- |
| `poll(timeout=0)` | one `Message` or None. `timeout=None` waits indefinitely. Raises `ValueError` once the collector is closed. |
| `messages(timeout=None)` | endless iterator of `Message` |
| `flows(now=None)` | endless iterator of `Flow` |
| `stop()` | end the iterators; safe from any thread |
| `close()` | release the socket; idempotent |
| `address` | the `(host, port)` actually bound, which matters when `port=0` |
| `stats` | the decoder's [counters](#counters) |
| `fileno()` | the socket descriptor |

---

## Decoder and Message

`Decoder` is the parsing layer with its state attached: the template store,
the sequence watch, the sampling watch. It has no socket in it.

```python
from netflume import Decoder

decoder = Decoder()                  # track_sequence=True, track_sampling=True
message = decoder.decode(data, "10.0.0.1")
```

`decode` returns a `Message`, or None if the datagram was too short, carried an
unsupported version, or would not parse. **It never raises**: a decoder that
dies on one bad packet is useless on a real network. Every failure is counted
and queued as a [`DecodeError`](#events).

A `Message` with no flows in it is not a failure. Template sets, option
records, and data sets whose template has not arrived yet all produce one, and
an exporter's first few datagrams are routinely all template.

| `Message` | |
| --- | --- |
| `.header` | the message header dict |
| `.flows` | list of flow record dicts |
| `.options` | list of option record dicts, what the exporter says about itself |
| `.gap` | exports the sequence counter says never arrived before this message |
| `.sampling_rate` | the 1-in-N rate in force for this message's exporter and observation domain |
| `.exporter`, `.version`, `.sequence` | read off the header |
| `.typed_flows(now=None)` | the flows as [`Flow`](#flow-the-typed-view) objects |

One `Decoder` serves every exporter sending to you. Templates, sequence
tracking and sampling are all keyed by `(exporter, observation domain)` inside,
because one chassis can run several domains, sample them differently and count
their sequence numbers separately. It is **not thread safe**. Give each thread
its own, or put one behind a queue.

---

## The flow shape

A flow record is a plain `dict`. The keys are normalised, so v5, v9 and IPFIX
produce the same key for the same idea and you write one schema, not three.

Every key is optional. Exporters send what they are configured to send, and
**absent is not zero**: a flow with no `octets` is not a flow that carried
nothing.

### Common keys

| key | from | meaning |
| --- | --- | --- |
| `src_addr`, `dst_addr` | IE 8/12, 27/28 | address strings. **IPv4 and IPv6 share these keys**, and one field carries either. A template carrying both families zero-fills the unused one, and the zeros never displace the populated family. |
| `src_port`, `dst_port` | IE 7, 11 | int |
| `proto` | IE 4 | IP protocol number |
| `octets`, `packets` | IE 1, 2 | this flow's counts |
| `octets_total`, `packets_total` | IE 85, 86 | **the same idea, different elements.** Exporters send one pair or the other. |
| `tcp_flags` | IE 6 | flags seen over the flow's life, as an int |
| `first_switched`, `last_switched` | IE 22, 21 | ms since the exporter booted (v5, v9) |
| `flow_start_ms`, `flow_end_ms` | IE 152, 153 | absolute epoch ms (IPFIX) |
| `flow_start_s`, `flow_end_s` | IE 150, 151 | absolute epoch seconds |
| `flow_start_us`, `flow_end_us` | IE 154, 155 | **UNIX seconds, as a float.** NTP on the wire, see below |
| `flow_start_ns`, `flow_end_ns` | IE 156, 157 | **UNIX seconds, as a float.** NTP on the wire, see below |
| `in_if`, `out_if` | IE 10, 14 | interface indices |
| `src_mask`, `dst_mask` | IE 9, 13 | prefix lengths |
| `src_as`, `dst_as` | IE 16, 17 | AS numbers |
| `next_hop` | IE 15, 62 | address string |
| `post_nat_src_addr`, `post_nat_dst_addr` | IE 225, 226 | **may be the only addresses present** |
| `tos`, `vlan`, `src_mac`, `dst_mac`, `if_name`, … | | see `netflume/ie.py` for the full table |

`netflume.IE` is that table, `{element id: (name, kind)}`, and it is the whole
list.

#### The microsecond and nanosecond timestamps are NTP

RFC 7011 §6.1.9 and §6.1.10 define `dateTimeMicroseconds` and
`dateTimeNanoseconds` as 64-bit **NTP** timestamps: seconds since 1900 in the
high word, and a fraction in units of 1/2³² in the low one. They are not counts
since the UNIX epoch. `dateTimeSeconds` and `dateTimeMilliseconds` (IE 150 to
153) *are* plain epoch counts, so only two of the four pairs are affected.

netflume converts them at decode time, so `flow_start_us` holds **UNIX seconds
as a float**, the same currency `flow_timestamp` deals in. The key name
describes the precision the information element declares, not the unit of the
value under it. Do not divide it by 1e6: reading the raw NTP word as
microseconds puts the flow in the year 540,000 and makes every duration 2³²/1e6
= 4295× too long.

An all-zero timestamp field decodes to `0`, meaning unset, rather than to
midnight in 1900.

### Keys you did not expect

Unrecognised elements are kept, not dropped:

- a standard element with no entry in the table → `ie<id>`, e.g. `ie9999`
- an enterprise-specific element → `e<enterprise>.<id>`, e.g. `e9.33`

A vendor field nobody has modelled is exactly what a forwarder might be built
to ship, so nothing is thrown away to keep the shape tidy.

### The header

| key | |
| --- | --- |
| `version` | 5, 9 or 10 |
| `exporter` | source address of the device, as a string |
| `domain` | observation domain; the engine ID for v5 |
| `sequence` | the export sequence counter |
| `unix_secs` | export time, epoch seconds |
| `sys_uptime` | ms since the exporter booted; None for IPFIX |

### Values

Addresses and MACs are strings; integers are ints; strings are decoded UTF-8
with trailing padding stripped. Anything the parser cannot make sense of
becomes an int if it is eight bytes or fewer, and a hex string otherwise. All
of it is JSON-native.

---

## Flow, the typed view

The dict is the parser's output and stays that way. `Flow` is an **opt-in**
wrapper over it, because a forwarder that wants three fields should not pay
to build thirty. What it is actually for is not the annotations; it is the
normalisations, each of which is otherwise open-coded at every call site:

```python
from netflume import Flow

flow = Flow.from_record(rec, hdr, sampling_rate=1, now=None)
```

- `flow.octets` reads `octets` **or** `octets_total`. Same for packets. Read
  `rec["octets"]` alone and every IE 85 exporter contributes zero bytes: a
  wrong total rather than a missing one, which is the harder kind to notice.
- `flow.src_addr` falls back to the post-NAT address when there is no other.
- `flow.start` is derived from the record **and the header**, which is why
  `from_record` takes both.
- everything optional stays `None`, never a sentinel zero.

| attribute | |
| --- | --- |
| `raw` | the parser's dict, not a copy. Treat as read-only. |
| `exporter`, `version`, `domain` | always present |
| `start` | flow start, unix epoch float. Always present, see below |
| `duration` | seconds, or None |
| `src_addr`, `dst_addr`, `src_port`, `dst_port`, `proto` | or None |
| `octets`, `packets`, `tcp_flags`, `in_if`, `out_if` | or None |
| `sampling_rate` | 1-in-N, or 1 |

| property / method | |
| --- | --- |
| `endpoints` | `(src, dst)` |
| `end` | `start + duration`, or None |
| `src_kind`, `dst_kind` | `"private"`, `"public"`, `"multicast"`, `"special"`, `"unknown"` |
| `is_external` | one end local, one not |
| `proto_name` | `"TCP"`, `"UDP"`, … or None |
| `service` | well known name for the **destination** port, or None |
| `flags` | `"...AP..."`, `""` if the exporter sent none |
| `started_at()` | `start` as an aware UTC datetime |
| `scaled(value)` | value corrected for the sampling rate; None in, None out |
| `get(key, default)` | any field of the record, modelled or not |
| `as_dict(include_raw=True)` | flat, JSON-safe dict |

`start` is best effort and never None. IPFIX absolute timestamps win; failing
those it is rebuilt from `first_switched` plus the header's uptime, and that
reconstruction is rejected in favour of the export time if it lands more than
a day away, which is what a wrapped uptime counter looks like.

### Getting out to plain data

```python
flow.as_dict()                    # every decoded field + metadata keys
flow.as_dict(include_raw=False)   # only MODELLED_FIELDS, a fixed column set
```

`as_dict()` adds `_exporter`, `_version`, `_timestamp`, `_domain`, `_duration`
and `_sampling_rate`, which together are `METADATA_KEYS`. They are underscored
so that they cannot collide with an information element name, present or
future.

`include_raw=False` gives `MODELLED_FIELDS` and nothing else, which is the form
a database table wants: no surprise columns when somebody plugs in a router
that sends a vendor element.

**Timestamps leave as unix epoch floats**, deliberately. Every database and
every message payload can store one without a serialiser, and `started_at()` is
one call away for anyone who wants a datetime.

---

## Events

Anything the console version would have printed is an object here.

```python
for event in decoder.take_events():
    ...
```

| class | fields | |
| --- | --- | --- |
| `SamplingChange` | `exporter`, `domain`, `rate`, `previous` | a domain stated, or restated, how much it is leaving out |
| `ExportGap` | `exporter`, `domain`, `version`, `missed`, `unit` | exports that never arrived |
| `DecodeError` | `exporter`, `reason`, `detail` | a datagram that would not decode. `reason` is `"short"`, `"unsupported"` or `"malformed"` |

`take_events()` hands over what has accumulated and forgets it. Empty is the
normal answer on a healthy network, so it is cheap to call in a loop. The queue
holds `MAX_PENDING_EVENTS` and then drops the oldest, counting each drop in
`decoder.stats["events_dropped"]`: a collector on an open UDP port receives
things that are not NetFlow, and a caller that never drains must not accumulate
one event per junk datagram for the life of the process. Each
class has a `__str__` that explains itself in a sentence, and each is also
written to the log.

---

## Sampling

An exporter that samples reports one flow in N, and its byte and packet counts
are correspondingly short. Nothing downstream can correct for that without
knowing N.

```python
decoder.sampling_rate("10.0.0.1", domain=0)   # 1000 means 1-in-1000. Never None.
flow.scaled(flow.octets)                      # the count corrected for it
```

Rates belong to an observation domain, not to a device, so name one. Omitting
`domain` asks about the exporter as a whole and answers only when that is
unambiguous: every domain heard from agrees, or only one has spoken. When they
disagree it returns 1 rather than applying one domain's rate to another's
counts.

The rate is read out of option records automatically, in every form exporters
advertise it: the v5 header word, `samplingInterval`, `samplerRandomInterval`,
IPFIX interval/space, and IPFIX size/population. A change raises a
`SamplingChange`. An exporter repeating the same rate, which they do in every
options record, raises one the first time and nothing after.

`sampling_rate(rec)` on its own, for a record you have in hand, returns None
when the record says nothing about sampling and 1 when it explicitly describes
an unsampled exporter. Those are different answers, and a caller holding a
stale rate needs to tell them apart.

---

## Export gaps

Every export message carries a sequence counter, and a jump in it means
messages went missing on the way here, whether a saturated link or this
process not keeping up. Without watching it the loss is silent: a flow that
never arrives looks exactly like a flow that never happened.

```python
message.gap              # exports missing before this message
decoder.export_gaps()    # cumulative, per stream, worst first
```

What the counter counts differs by version: v5 counts flow records, IPFIX
counts data records, and v9 is *specified* to count export packets but is
widely built to count records instead. Rather than trust the version, each
stream is watched until one reading lands exactly on the next message, and that
becomes the rule for that stream. **Until one does, nothing is reported**,
since a wrong rule would invent a loss on every message, and a collector that
cries wolf about dropped flows is worse than one that stays quiet. An exporter
sending a single record per message is ambiguous forever and is watched without
ever being judged.

Repeats, reordering and counter restarts are recognised and are not losses.
Streams are keyed by `(exporter, domain, version)` and never summed together:
adding a count of export messages to a count of data records gives a number
that means nothing, which is why `ExportGap` carries its `unit`.

---

## Counters

`collector.stats` / `decoder.stats` is a `collections.Counter`. Absent means
zero.

| key | |
| --- | --- |
| `packets` | datagrams received |
| `bytes_rx` | bytes received |
| `flows` | flow records decoded |
| `option_records` | option records decoded |
| `templates_new` | templates learned or changed |
| `deferred` | data sets dropped because their template had not arrived |
| `malformed` | datagrams too short, or with a truncated header |
| `unsupported_version` | not v5, v9 or IPFIX, usually sFlow on the wrong port |
| `parse_errors` | datagrams whose body would not parse |
| `missed_exports` | total gap, all streams |
| `v5_msgs`, `v9_msgs`, `v10_msgs` | messages per version |
| `events_dropped` | events discarded because the queue was full, see [Events](#events) |

`deferred` climbing at the start is normal and not a fault: v9 and IPFIX
exporters resend templates periodically, often every few minutes, and data
before the first one cannot be decoded by anybody.

---

## Ceilings

Every table keyed by exporter has a ceiling. A UDP source address is whatever
the sender typed, so anything keyed by one and never evicted is a memory leak
that anyone able to reach the socket can pull on.

| constant | default | what it bounds | on overflow |
| --- | --- | --- | --- |
| `netflume.parse.MAX_TEMPLATES` | 10,000 | learned templates | least recently used evicted |
| `netflume.sequence.MAX_STREAMS` | 10,000 | tracked `(exporter, domain, version)` streams, and their gap counters | least recently seen evicted |
| `netflume.sampling.MAX_SAMPLING_STREAMS` | 10,000 | remembered sampling rates | least recently seen evicted |
| `netflume.decoder.MAX_PENDING_EVENTS` | 10,000 | events awaiting `take_events()` | oldest dropped, counted in `stats["events_dropped"]` |
| `netflume.values.MAX_SERVICE_CACHE` | 100,000 | cached service-name lookups | stops caching |

`TemplateStore`, `SequenceWatch` and `SamplingWatch` each take the limit as a
constructor argument, so a collector facing an unusual number of exporters can
raise it rather than patch the module.

The defaults are far above any real deployment, since a collector sees tens of
exporters, each with a handful of domains and templates. Eviction is not free
when it happens. **Evicting a template means the flows in its data sets
are undecodable until the exporter resends it**, commonly one to ten minutes
later. Reading a template counts as using it, so a template still receiving
data survives a flood of addresses that never send any. Watch
`decoder.templates.evicted`, `decoder.sequence.evicted` and
`decoder.sampling.evicted`; all three should stay at zero.

---

## Logging

Everything goes to the `netflume` logger. The package installs a
`NullHandler` and nothing else, so records go nowhere until you configure a
handler.

```python
import logging
logging.basicConfig(level=logging.INFO)
```

| logger | what |
| --- | --- |
| `netflume.collector` | INFO once at bind, DEBUG for a refused `SO_RCVBUF` and for stale ICMP errors |
| `netflume.sampling` | WARNING when a domain starts sampling, INFO when it stops |
| `netflume.sequence` | WARNING on the first gap for an exporter |
| `netflume.decoder` | DEBUG per undecodable datagram |

---

## Hostname resolution

**Not in this package.** It lives in
[lanname](https://github.com/mjaksn/lanname), which turns an address into a
name by reverse DNS, mDNS or NetBIOS, caches the answer, and never blocks the
caller asking for it.

```
pip install lanname
```

```python
from lanname import Resolver

with Resolver(mode="dns", workers=4) as resolver:
    name = resolver.lookup(flow["src_addr"])   # None until it is known
```

It used to be an optional module here, `netflume.names`, and it moved out
because nothing in this package ever imported it and nothing about it was
specific to flow records. Nothing here depends on it now; install it if a
consumer wants names, and skip it otherwise. A database logger usually does
want them, an IP address in a year-old row being much less useful than a
hostname.

Two of its properties are worth knowing before it goes anywhere near a
collector, and both are the reasons it is separate rather than wired in.
`lookup()` reads a cache and returns immediately, because UDP has no
backpressure and anything that blocks a receive loop drops flows silently. And
its widest mode sends probes onto the LAN, which is why it does nothing at all
until a mode is chosen.

---

## Parsing without a socket

```python
from netflume import TemplateStore, parse_message

store = TemplateStore()      # must outlive the datagram
for data, exporter in datagrams_from_a_pcap():
    hdr, flows, options = parse_message(data, exporter, store)
```

`parse_message` dispatches on the version and raises `ValueError` for one it
does not decode, so an unsupported exporter and a truncated datagram stay
distinguishable. `parse_v5` and `parse_v9_or_ipfix` are there if you already
know which you have.

The store must persist across datagrams. Exporters resend templates only
periodically, and a data set arriving before its template cannot be decoded at
all, which is what `deferred` counts.

Also exported, for a caller working with the records directly: `flow_endpoints`,
`flow_timestamp`, `flow_duration`.

---

## Sketch: logging flows to a database

Real `sqlite3`, so it runs, but the shape is what matters. Swap in whatever
you actually use. `MODELLED_FIELDS` is the column set precisely so that a new
exporter on the network does not mean a migration.

```python
import signal
import sqlite3

from netflume import Collector, MODELLED_FIELDS
from netflume.events import ExportGap, SamplingChange

COLUMNS = ", ".join(MODELLED_FIELDS)
PLACEHOLDERS = ", ".join("?" * len(MODELLED_FIELDS))

db = sqlite3.connect("flows.db")
db.execute(f"CREATE TABLE IF NOT EXISTS flows ({COLUMNS})")

collector = Collector(port=2055)
signal.signal(signal.SIGTERM, lambda *_: collector.stop())

batch = []
with collector, db:
    for message in collector.messages():
        for flow in message.typed_flows():
            row = flow.as_dict(include_raw=False)
            batch.append([row[name] for name in MODELLED_FIELDS])

        # Batched: one commit per flow would spend the whole time in fsync,
        # and a stalled receive loop drops datagrams with no way to know.
        if len(batch) >= 500:
            db.executemany(
                f"INSERT INTO flows ({COLUMNS}) VALUES ({PLACEHOLDERS})", batch)
            db.commit()
            batch.clear()

        for event in collector.decoder.take_events():
            if isinstance(event, ExportGap):
                # Rows are missing and the table cannot show that by itself.
                # Record it, or the gap becomes a quiet lie about the traffic.
                # Store the whole stream key: gaps from different domains or
                # versions count different things and must never be summed.
                record_gap(event.exporter, event.domain, event.version,
                           event.missed, event.unit)
            elif isinstance(event, SamplingChange):
                # Every count from this domain is now 1/N of the truth. The
                # rate belongs to the domain, not to the device, so a second
                # domain would otherwise overwrite the first.
                record_sampling(event.exporter, event.domain, event.rate)
```

Three things worth doing that the sketch only gestures at:

- **Store the sampling rate alongside the rows**, not in a separate config. It
  changes while you are running, and a row is only interpretable with the rate
  that was in force when it arrived. `flow.sampling_rate` is already on each
  flow for this reason.
- **Keep the writes off the receive loop** once the flow rate is more than a
  home link. A bounded `queue.Queue` and a writer thread; drop on a full queue
  and count it, because blocking the reader loses datagrams silently, which is
  strictly worse than knowingly dropping a flow.
- **Store `raw` too** if you may ever want a field you did not model. A JSON
  column of `flow.as_dict()` costs space but means an exporter's vendor
  elements are still there when someone asks.

---

## Sketch: forwarding a subset over MQTT

Pseudocode for the client; no MQTT library is a dependency here.

```python
import json

from netflume import Collector

client = connect_to_broker()          # your MQTT client of choice

with Collector(port=2055) as collector:
    for rec, hdr in collector:
        # The dict form, not the typed one: three fields do not justify
        # building an object per flow, and a busy exporter sends tens of
        # thousands a second into a single-threaded loop.
        if rec.get("dst_port") not in WATCHED_PORTS:
            continue

        topic = f"netflow/{hdr['exporter']}/{rec.get('proto')}"
        client.publish(topic, json.dumps({
            "src": rec.get("src_addr"),
            "dst": rec.get("dst_addr"),
            "port": rec.get("dst_port"),
            "bytes": rec.get("octets", rec.get("octets_total")),
        }))
```

Notes for a real one:

- **Filter before you serialise.** Most flows are not interesting, and the
  cheapest flow is the one you never build a payload for.
- **`octets` or `octets_total`**, as above. If you find yourself writing that
  `.get(..., .get(...))` more than once, use `Flow` and let it do it.
- **Publish sampling changes on their own topic.** A subscriber doing
  arithmetic on byte counts needs to know the multiplier changed, and it will
  never guess.
- **Do not block the receive loop on the broker.** A publish that waits for a
  reconnect stalls the reader, and UDP has no backpressure. Hand payloads to a
  bounded queue and let a publisher thread drain it.

---

## Protocol support

| version | header | templates | notes |
| --- | --- | --- | --- |
| NetFlow v5 | 24 bytes | none, fixed 48-byte records | fully decoded on the first packet |
| NetFlow v9 | 20 bytes | FlowSet 0 (data), 1 (options) | |
| IPFIX / v10 | 16 bytes | Set 2 (data), 3 (options) | enterprise fields and variable-length encoding |

Templates are keyed by `(exporter address, observation domain, template ID)`.
Different exporters reuse the same IDs for different layouts, so all three are
needed.

IPFIX variable-length fields are handled in both forms: a declared length of
`0xFFFF` means a one-byte length prefix, or `0xFF` followed by a two-byte
length for values of 255 bytes or more.

Option records are decoded and returned **separately from flows**. They
describe the exporter, not traffic; mixed into the flow list they look like
flows with no addresses and inflate every count downstream. The sampling rate
is read out of them automatically; interface names, application ID mappings and
the rest are decoded and handed to you to use or ignore.

Set lengths, record lengths and template field counts are all bounds-checked. A
malformed datagram is counted and discarded, never raised.

---

## Tests

```bash
python -m unittest discover
```

273 tests, no dependencies, about a second. Several use `subTest`, so the
number of individual checks is higher than the number of tests.

The suite is built around synthetic messages assembled byte by byte in
`tests/packets.py`, which means the awkward cases are reachable: a template set
carrying several templates, an options template whose scope length overruns its
set, a data record truncated mid-field, a message that ends inside its own
header. Every prefix of a full message is decoded, so anything that would only
break on a fragment breaks in the suite first.

`tests/test_hardening.py` covers the cases that decode without raising and
return something untrue, which is the failure class the fuzzer cannot see: NTP
timestamps read as epoch counts, a truncated template fabricating flows, a
dual-stack template erasing its own addresses, a sampling rate wiped by another
observation domain, and the [ceilings](#ceilings), which are asserted rather
than assumed.

`Decoder.decode` promises never to raise, and that promise is attacked rather
than trusted:

```bash
python tools/fuzz.py --seconds 60
```

It mutates valid v5, v9 and IPFIX messages with bit flips, truncations,
splices and implausible length fields, then asserts nothing escapes. One
decoder runs across the whole session, so template state accumulates and a
later datagram meets
whatever an earlier one left behind. A failure prints a hex reproducer and the
seed that produced it.

Everything is synthetic. No real exporter was involved, so what the suite proves
is conformance to the specifications and to its own reading of them, not
agreement with any particular vendor's interpretation.

---

## Limitations

- **No sFlow.** Different protocol, different wire format. It arrives on the
  same port often enough that `unsupported_version` is worth watching.
- **No IPv6 transport.** The socket is `AF_INET`. IPv6 addresses *inside* flow
  records decode fine; the exporter has to reach you over IPv4. On the roadmap.
- **Single-threaded receive.** One `Collector`, one socket, one reader. Under
  heavy load, move the socket read into its own thread feeding a bounded queue,
  and watch `missed_exports`, which is how you find out you needed to.
- **`Decoder` is not thread safe.** One per thread, or one behind a queue.
- **Per-exporter state is capped and evicts.** See [Ceilings](#ceilings). The
  defaults are far above a real deployment, but a collector facing tens of
  thousands of distinct source addresses, or a spoofing flood, loses the
  least recently used templates and cannot decode their flows until the
  exporter resends.
- **A truncated template is refused, not salvaged.** A template set that ends
  mid-template is dropped rather than stored short, so the flows in that
  datagram are lost. The alternative is worse: a template missing fields cuts
  every later record for that ID into one real flow plus fabricated ones, and
  those reach the caller as genuine traffic until the next template refresh.
- **No persistence, no aggregation, no alerting.** By design; that is what the
  two sketches above are for. Template *state* is a different question and is
  on the roadmap. See below for why a restart currently costs you flows.
- **Flow data is 5-tuple only.** No SNI, no JA3, no DNS names, no payload. If
  you need those, NetFlow is the wrong data source and a mirror port is the
  right one.

---

## Everything else exported

The sections above cover what most callers need. Everything below is public
API too, listed here so that the export list and the documentation agree.

Names written bare are exported from the package itself, as in `from netflume
import service_name`. Names written with a module path are exported from that
module only, so `from netflume.parse import NTP_EPOCH` works and `from netflume
import NTP_EPOCH` does not.

| name | |
| --- | --- |
| `SequenceWatch`, `SamplingWatch` | the trackers behind [export gaps](#export-gaps) and [sampling](#sampling), usable on their own against records you already hold |
| `sampling_rate(rec)` | read a 1-in-N rate out of one option record: `None` for silence, `1` for explicitly unsampled |
| `addr_kind(addr)` | `"private"`, `"public"`, `"multicast"`, `"special"` or `"unknown"`; `ADDR_KINDS` is the tuple |
| `service_name(port, proto)` | well-known service name, or `None` for ephemeral ports and non-TCP/UDP |
| `netflume.values.EPHEMERAL_FLOOR` | the port at which `service_name` stops naming, for a consumer drawing the same line |
| `proto_name(proto)`, `PROTO_NAMES` | IP protocol number to name |
| `tcp_flags_str(flags)`, `TCP_FLAG_BITS` | flag byte to a readable string |
| `flow_end_reason_name(code)`, `FLOW_END_REASON` | IE 136 code to a description |
| `DEFAULT_PORT`, `DEFAULT_RCVBUF` | 2055, and the 4 MB receive buffer `Collector` asks for |
| `SUPPORTED_VERSIONS` | `(5, 9, 10)` |
| `netflume.parse.NTP_EPOCH` | 2208988800, for the timestamp conversion described [above](#the-microsecond-and-nanosecond-timestamps-are-ntp) |
| `netflume.parse.UNSPECIFIED` | the values treated as "not filled in" when a template repeats a key |

The ceiling constants are in [Ceilings](#ceilings).

---

## Roadmap

Planned, not promised, and ordered within each group by expected value. The
three headings are the three things this package optimises for.

### Performance

- **Template-compiled unpacking.** When every field in a template is
  fixed-length, which is the common case, the layout is known the moment the
  template is learned. Building one `struct.Struct` per template and unpacking
  a whole record in a single call replaces per-field slicing and integer
  conversion.
  This is the largest single decode win available and the reason the template
  store is a first-class object rather than a dictionary.
- **`memoryview` over the datagram.** Field extraction currently slices, and a
  slice copies. A view does not.
- **Selective decoding.** An optional field allow-list on the `Decoder`, so a
  forwarder that publishes five fields stops paying to decode forty. The wire
  offsets still have to be walked; the values do not have to be built.
- **A benchmark suite, tracked in CI.** Flows per second by version and by
  template shape, so the claims above become measurements and a regression
  shows up as a number rather than as a complaint.

### Versatility

- **Collection over IPv6.** An `AF_INET6` socket with `IPV6_V6ONLY` cleared,
  so exporters reaching the collector over IPv6 are decodable at all. This is
  about the *transport*; IPv6 addresses inside flow records already decode, and
  a template carrying both families is handled under
  [Common keys](#common-keys).
- **An asyncio interface.** `async for flow in collector` for daemons already
  built around an event loop, without the thread-and-queue adapter every such
  caller currently writes.
- **A persistent template store.** v9 and IPFIX data records are undecodable
  until their template arrives, and exporters resend templates on their own
  schedule, commonly every one to ten minutes. A process restart therefore
  drops every flow until each exporter happens to resend. Saving and restoring
  the store removes that window, and matters more than anything else here for a
  long-running daemon.
- **An enterprise element registry.** Vendor elements decode today as
  `e<pen>.<id>` with raw bytes. Letting a caller register a name, a type and a
  length turns a vendor's flow direction or application ID into a first-class
  field.
- **A capture source.** Reading datagrams from a pcap or a flat file, for
  replaying a problem, testing a consumer against real traffic, and attaching
  something reproducible to a bug report.

### Ease of use

- **`python -m netflume`.** A JSONL dump to stdout, enough to confirm an
  exporter is configured correctly and reaching you before any code is written
  against it. Not a console application; a smoke test.
- **Wider modelling on `Flow`.** More fields promoted from the raw dict, with
  the aliasing handled once, as the existing four are.
- **Worked consumers.** The [database](#sketch-logging-flows-to-a-database) and
  [MQTT](#sketch-forwarding-a-subset-over-mqtt) sketches carried through to
  runnable examples, including the parts that are easy to get wrong: batching,
  back-pressure, and what to do when the sink is slower than the exporter.

Explicit non-goals: sFlow, which is a different protocol rather than a variant;
aggregation, alerting and storage, which belong to the consumer; and any form
of presentation.

---

## Licence

MIT. See [LICENSE](https://github.com/mjaksn/netflume/blob/main/LICENSE).
