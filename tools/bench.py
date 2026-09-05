#!/usr/bin/env python3
"""Measure how fast the parse path decodes, so a change can be judged.

The README promises that a regression shows up as a number rather than as a
complaint, and nothing can be optimised before it can be measured. This is the
before. It exists mainly for the template compilation work, which claims a
large speedup on v9 and IPFIX and needs something to claim it against.

    python tools/bench.py                       # every case, human readable
    python tools/bench.py --only ipfix          # just the IPFIX cases
    python tools/bench.py --json                # machine readable
    python tools/bench.py --save bench.json     # write a baseline
    python tools/bench.py --baseline bench.json # compare against one

Standard library only and no fixture or service, exactly like the suite and
the fuzzer. The corpus is built from `tests/packets.py`, so what is measured
here is the same synthetic traffic the tests assert on.

What a record means varies by case and the table says so: it is a flow
everywhere except `ipfix-options`, where an options template produces option
records and no flows at all, and `flow-from-record` has no datagram to count
because it measures the typed layer over records already decoded.

Every case is decoded once and checked against the record count it should
produce before anything is timed. A benchmark that silently measures a parse
returning nothing is worse than no benchmark, because it reports a number and
the number looks fine.
"""

import argparse
import json
import os
import platform
import statistics
import sys
import timeit

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

import netflume  # noqa: E402
from netflume import Flow, TemplateStore, parse_message  # noqa: E402
from tests import packets as p  # noqa: E402

#: Records per datagram. 24 is what the recorded baseline used, and changing
#: it makes every number here incomparable with the ones already published.
PER_DATAGRAM = 24

#: Sixteen fixed-length fields of the shape a router actually exports. The
#: recorded baseline used a template of this width, so the wide cases are the
#: ones to compare against it.
WIDE_FIELDS = [
    (8, 4), (12, 4), (7, 2), (11, 2), (4, 1), (1, 4), (2, 4),   # the narrow set
    (6, 1), (10, 4), (14, 4), (5, 1), (16, 4), (17, 4), (9, 1), (13, 1),
    (152, 8),
]

#: A variable-length element (interfaceName) on the end of the narrow set.
#: IPFIX spells "the record declares this width" as 0xFFFF in the template.
VARLEN_FIELDS = p.FLOW_FIELDS + [(82, 0xFFFF)]

#: An options template: one scope field and four option fields. Exporters use
#: these to describe themselves, and they are the reason option records are
#: kept apart from flows everywhere else in the package.
OPTION_SCOPE = [(145, 4)]
OPTION_FIELDS = [(34, 4), (35, 4), (36, 4), (37, 4)]

#: The recorded environment key naming what was measured rather than where.
#: Every other key describes a machine or an interpreter, and throughput is
#: only comparable within those. This one is the version of the code under
#: test, so it is meant to differ between a baseline and the run being judged
#: against it: that difference is the comparison the baseline exists to make,
#: and warning about it would fire on every run after a version bump.
VERSION_KEY = "netflume"


def payload_for(fields, seed=0):
    """One record's worth of bytes for a template of `fields`.

    The values only have to be decodable, but they are not random: a fixed
    payload keeps a run comparable with the one before it, and randomness
    would buy nothing here because the decoder does the same work either way.
    """
    out = bytearray()
    for i, (_, length) in enumerate(fields):
        if length == 0xFFFF:
            text = f"eth{(seed + i) % 10}".encode()
            out += bytes([len(text)]) + text
        else:
            out += ((seed + i + 1) % 251 + 1).to_bytes(1, "big") * length
    return bytes(out)


def data_datagram(build, tid, fields, count=PER_DATAGRAM):
    """A message carrying `count` data records and no template.

    The template is learned separately and once, because an exporter sends it
    every few minutes rather than with every datagram, and folding it into the
    thing being timed would measure the wrong event.
    """
    payload = b"".join(payload_for(fields, seed=i) for i in range(count))
    return bytes(build([p.data_set(tid, payload)]))


def v5_datagram(count=PER_DATAGRAM):
    return bytes(p.v5_message(count=count))


def learn(build, template_set):
    """A store with one template already in it, as a running collector has."""
    store = TemplateStore()
    parse_message(bytes(build([template_set])), "10.0.0.1", store)
    store.take_events()
    return store


def build_cases():
    """Every case: a name, a callable to time, and what it should return.

    Each entry carries the record count it must produce so that the check
    below can refuse to time a case that is quietly decoding nothing.
    """
    cases = []

    # == NetFlow v5, the path that is already fast =========================
    v5 = v5_datagram()
    cases.append(("v5", lambda: parse_message(v5, "10.0.0.1"),
                  PER_DATAGRAM, "flows"))

    # == v9 and IPFIX, narrow and wide =====================================
    for name, build, template_of in (
            ("v9", p.v9, p.v9_data_template),
            ("ipfix", p.ipfix, p.data_template)):
        for width, fields in (("narrow", p.FLOW_FIELDS), ("wide", WIDE_FIELDS)):
            tid = 400 if width == "narrow" else 401
            store = learn(build, template_of(tid, fields))
            data = data_datagram(build, tid, fields)
            cases.append((
                f"{name}-{width}",
                # Default arguments bind this iteration's values; a closure
                # over the loop variables would time the last case only.
                lambda d=data, s=store: parse_message(d, "10.0.0.1", s),
                PER_DATAGRAM, "flows"))

    # == the variable-length walk, which template compilation cannot help ==
    store = learn(p.ipfix, p.data_template(402, VARLEN_FIELDS))
    varlen = data_datagram(p.ipfix, 402, VARLEN_FIELDS)
    cases.append(("ipfix-varlen",
                  lambda d=varlen, s=store: parse_message(d, "10.0.0.1", s),
                  PER_DATAGRAM, "flows"))

    # == option records, which are counted apart from flows everywhere =====
    store = learn(p.ipfix, p.ipfix_options_template(403, OPTION_SCOPE,
                                                    OPTION_FIELDS))
    opts = data_datagram(p.ipfix, 403, OPTION_SCOPE + OPTION_FIELDS)
    cases.append(("ipfix-options",
                  lambda d=opts, s=store: parse_message(d, "10.0.0.1", s),
                  PER_DATAGRAM, "option records"))

    # == the typed layer, measured over records already decoded ============
    store = learn(p.ipfix, p.data_template(404, WIDE_FIELDS))
    hdr, flows, _ = parse_message(data_datagram(p.ipfix, 404, WIDE_FIELDS),
                                  "10.0.0.1", store)
    cases.append((
        "flow-from-record",
        lambda recs=flows, h=hdr: [Flow.from_record(r, h) for r in recs],
        PER_DATAGRAM, "flows"))

    return cases


def check(cases):
    """Run every case once and hold it to the record count it promised.

    This is the whole reason the counts are carried around. A template that
    failed to be learned parses its data sets into nothing at all, quickly,
    and without it this harness would report that as excellent throughput.
    """
    for name, fn, expected, unit in cases:
        got = fn()
        if isinstance(got, tuple):
            _, flows, options = got
            count = len(options) if unit == "option records" else len(flows)
        else:
            count = len(got)
        if count != expected:
            raise SystemExit(
                f"case {name} decoded {count} {unit}, expected {expected}. "
                f"The corpus and the decoder disagree, so nothing is timed.")


def measure(fn, repeat):
    """Median seconds per call, over `repeat` runs of an autoranged batch.

    The median rather than the mean because a run that lost the CPU to
    something else is an outlier rather than a slow decoder, and the minimum
    because it flatters a noisy machine into looking quiet.
    """
    timer = timeit.Timer(fn)
    number, _ = timer.autorange()
    runs = timer.repeat(repeat=repeat, number=number)
    return statistics.median(runs) / number


def environment():
    """Where a number was taken, and what version produced it.

    Only the first four keys bear on whether two numbers can be compared. See
    VERSION_KEY for why the last is recorded but not compared.
    """
    return {
        "python": platform.python_version(),
        "implementation": platform.python_implementation(),
        "system": platform.system(),
        "machine": platform.machine(),
        VERSION_KEY: netflume.__version__,
    }


def run(cases, repeat):
    results = {}
    for name, fn, expected, unit in cases:
        per_call = measure(fn, repeat)
        entry = {
            "unit": unit,
            "records_per_datagram": expected,
            "seconds_per_call": per_call,
            "records_per_second": expected / per_call,
        }
        # The typed layer is handed records that are already decoded, so it
        # has no datagram to be a rate of.
        if name != "flow-from-record":
            entry["datagrams_per_second"] = 1.0 / per_call
        results[name] = entry
    return results


def report(results, baseline=None):
    width = max(len(n) for n in results)
    head = f"{'case':<{width}}  {'records/s':>12}  {'datagrams/s':>12}"
    if baseline:
        head += f"  {'vs base':>9}"
    print(head)
    print("-" * len(head))
    for name, entry in results.items():
        dps = entry.get("datagrams_per_second")
        line = (f"{name:<{width}}  {entry['records_per_second']:>12,.0f}  "
                f"{(f'{dps:,.0f}' if dps else 'n/a'):>12}")
        if baseline:
            was = baseline.get("cases", {}).get(name, {})
            if was.get("records_per_second"):
                change = (entry["records_per_second"]
                          / was["records_per_second"] - 1) * 100
                line += f"  {change:>+8.1f}%"
            else:
                line += f"  {'new':>9}"
        print(line)

    units = {e["unit"] for e in results.values()}
    if len(units) > 1:
        print()
        print("a record is a flow except in ipfix-options, where it is an "
              "option record")


def compare_environments(now, was):
    """Say so when a baseline was taken somewhere else.

    Throughput is not portable between machines or interpreters, and a delta
    across two of them is a measurement of the difference between them. A
    moved VERSION_KEY is not that and is skipped, or the warning would land
    on every run once the version is bumped past the baseline's.
    """
    drift = [k for k, v in was.items()
             if k != VERSION_KEY and now.get(k) != v]
    if drift:
        detail = ", ".join(f"{k}: {was[k]} then, {now.get(k)} now"
                           for k in drift)
        print(f"warning: the baseline was taken elsewhere ({detail}). "
              f"The percentages below compare two environments, not two "
              f"versions of the code.")
        print()


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--repeat", type=int, default=5,
                    help="timed runs per case, medianed (default 5)")
    ap.add_argument("--only", metavar="TEXT",
                    help="run only cases whose name contains TEXT")
    ap.add_argument("--json", action="store_true",
                    help="write the results as JSON to stdout")
    ap.add_argument("--save", metavar="FILE",
                    help="write the results to FILE as a baseline")
    ap.add_argument("--baseline", metavar="FILE",
                    help="compare against a baseline written by --save")
    args = ap.parse_args()

    cases = build_cases()
    if args.only:
        cases = [c for c in cases if args.only in c[0]]
        if not cases:
            raise SystemExit(f"no case matches {args.only!r}")
    check(cases)

    baseline = None
    if args.baseline:
        # Read before timing rather than after. A missing or malformed
        # baseline is a typo nine times out of ten, and finding it after
        # several seconds of measuring is a waste of both.
        try:
            with open(args.baseline, encoding="utf-8") as fh:
                baseline = json.load(fh)
        except OSError as exc:
            raise SystemExit(f"cannot read baseline {args.baseline}: "
                             f"{exc.strerror}") from None
        except json.JSONDecodeError as exc:
            raise SystemExit(f"baseline {args.baseline} is not valid JSON: "
                             f"{exc}") from None

    results = run(cases, args.repeat)
    payload = {
        "environment": environment(),
        "repeat": args.repeat,
        "cases": results,
    }

    if args.json:
        json.dump(payload, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
    else:
        env = environment()
        print(f"netflume {env['netflume']} on "
              f"{env['implementation']} {env['python']}, "
              f"{env['system']} {env['machine']}, "
              f"median of {args.repeat} runs")
        print()
        if baseline:
            compare_environments(env, baseline.get("environment", {}))
        report(results, baseline)

    if args.save:
        with open(args.save, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, sort_keys=True)
            fh.write("\n")
        if not args.json:
            print()
            print(f"baseline written to {args.save}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
