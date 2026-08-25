#!/usr/bin/env python3
"""Throw malformed datagrams at the decoder and see whether it keeps its word.

``Decoder.decode`` promises never to raise: a datagram it cannot make sense of
becomes a ``DecodeError`` event and a counter, because a decoder that dies on
one bad packet is useless on a real network. That promise is worth testing
adversarially rather than trusting, because this is the one part of the package
that reads bytes chosen by whoever can reach the socket. Nothing else here
faces anything hostile.

    python tools/fuzz.py                  # ten seconds, random seed
    python tools/fuzz.py --seconds 60
    python tools/fuzz.py --seed 12345     # reproduce a reported failure

Any escape is printed as a hex reproducer and the run exits non-zero.
"""

import argparse
import os
import random
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from netflume import Decoder  # noqa: E402
from tests import packets as p  # noqa: E402


def seed_corpus():
    """Valid messages of each version, to mutate into invalid ones.

    Starting from something well formed reaches the interesting failures:
    entirely random bytes are rejected at the version check and never touch a
    template or a variable length field.
    """
    corpus = [
        p.v5_message(),
        p.ipfix([p.data_template(400, p.FLOW_FIELDS),
                 p.data_set(400, p.flow_payload())]),
        p.ipfix([p.ipfix_options_template(300, [(145, 4)], [(34, 4)]),
                 p.data_set(300, b"\x00\x00\x03\xe7\x00\x00\x03\xe8")]),
        p.v9([p.v9_data_template(500, p.FLOW_FIELDS),
              p.data_set(500, p.flow_payload())]),
        p.v9([p.v9_options_template(501, [(145, 4)], [(34, 4)]),
              p.data_set(501, b"\x00\x00\x03\xe7\x00\x00\x03\xe8")]),
    ]
    # A template set holding several templates: legal, easy to get wrong, and
    # a shape worth keeping under scrutiny.
    corpus.append(p.ipfix([p.template_set([(400, p.FLOW_FIELDS),
                                           (401, p.FLOW_FIELDS)])]))
    return [bytes(message) for message in corpus]


def mutate(rng, data):
    """One arbitrary corruption of a datagram."""
    if not data:
        return os.urandom(rng.randrange(0, 64))
    out = bytearray(data)
    how = rng.randrange(6)
    if how == 0:                                    # flip some bits
        for _ in range(rng.randrange(1, 8)):
            at = rng.randrange(len(out))
            out[at] ^= 1 << rng.randrange(8)
    elif how == 1:                                  # cut it short
        out = out[:rng.randrange(len(out) + 1)]
    elif how == 2:                                  # tack rubbish on the end
        out += os.urandom(rng.randrange(1, 64))
    elif how == 3:                                  # overwrite a run of bytes
        at = rng.randrange(len(out))
        run = os.urandom(min(rng.randrange(1, 16), len(out) - at))
        out[at:at + len(run)] = run
    elif how == 4:                                  # splice two datagrams
        other = rng.choice(seed_corpus())
        cut = rng.randrange(len(out) + 1)
        out = out[:cut] + bytearray(other)
    else:                                           # claim a silly length
        if len(out) >= 4:
            at = rng.choice([2, 4]) if len(out) > 6 else 2
            out[at:at + 2] = rng.randrange(0x10000).to_bytes(2, "big")
    return bytes(out)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--seconds", type=float, default=10.0,
                    help="how long to run for (default 10)")
    ap.add_argument("--seed", type=int, default=None,
                    help="fix the seed to reproduce a run")
    args = ap.parse_args()

    seed = args.seed if args.seed is not None else random.randrange(2 ** 32)
    rng = random.Random(seed)
    corpus = seed_corpus()
    print(f"seed {seed}, {args.seconds:g}s, {len(corpus)} seed messages")

    # One decoder across the whole run, so template state accumulates and a
    # later datagram meets whatever an earlier one left behind. Bugs live
    # there as often as in any single packet.
    decoder = Decoder()
    deadline = time.time() + args.seconds
    tried = 0
    decoded = 0

    while time.time() < deadline:
        data = mutate(rng, rng.choice(corpus))
        tried += 1
        try:
            message = decoder.decode(data, "10.0.0.1")
        except Exception as exc:
            print()
            print(f"decode() raised {type(exc).__name__}: {exc}")
            print(f"reproduce with: python tools/fuzz.py --seed {seed}")
            print(f"datagram ({len(data)} bytes): {data.hex()}")
            # from None: the details are printed above, and a chained
            # traceback here would bury them.
            raise SystemExit(1) from None
        if message is not None:
            decoded += 1
        # Keep the event queue from growing without bound over a long run.
        decoder.take_events()

    print(f"{tried} datagrams, {decoded} of them decoded to a message, "
          f"none raised")
    print(f"decoder stats: {dict(decoder.stats)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
