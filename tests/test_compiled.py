"""The compiled decode path held equal to the field-by-field walk.

A fixed-length template is compiled into one ``struct.Struct`` when it is
learned, and its records are read through that instead of walked a field at a
time. A difference between the two would not raise, so the fuzzer could not see
it; it would return something untrue, which is the failure class
``tests/test_hardening.py`` exists for. This file is that net, cast wide: both
paths are run over the same datagrams and everything a caller could observe is
required to match.

The walk stays reachable only for this. ``TemplateStore._compile = False``
keeps every template on it.
"""

import importlib.util
import os
import random
import struct
import unittest
from unittest import mock

from netflume import Decoder, TemplateStore
from netflume.parse import compile_template, parse_v9_or_ipfix

from . import packets as p

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

_spec = importlib.util.spec_from_file_location(
    "netflume_fuzz_harness", os.path.join(ROOT, "tools", "fuzz.py"))
fuzz = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(fuzz)

#: How many mutated datagrams make the fuzz corpus. Enough to reach the odd
#: shapes, few enough that the suite still runs in about a second.
MUTATIONS = 2000


def payload(fields, seed=0):
    """One record for `fields`, deterministic, with every byte doing work."""
    rng = random.Random(seed)
    return b"".join(rng.randbytes(length) for _eid, length in fields)


def record_set(fields, count=3):
    return b"".join(payload(fields, seed=i) for i in range(count))


#: Layouts chosen to reach every branch of the compiler: the direct integer
#: codes, the widths that are not one of them, every declared kind that still
#: converts, an IPv4 field of the wrong width, elements nobody has named, a
#: zero-length field, and a key repeated across the address families.
SHAPES = {
    "flow": p.FLOW_FIELDS,
    "odd integer widths": [(1, 3), (2, 6), (10, 5), (14, 7), (4, 1), (16, 16)],
    "every converting kind": [(56, 6), (82, 8), (154, 8), (27, 16), (8, 4)],
    "address of the wrong width": [(8, 3), (12, 16), (7, 2)],
    "unnamed elements": [(9999, 3), (9998, 12), (9997, 8), (9996, 1)],
    "a zero-length field": [(8, 4), (7, 0), (12, 4)],
    "nothing but zero-length fields": [(7, 0), (11, 0)],
}


def dual_stack_messages():
    """A template carrying both families, filled one way and then the other.

    IE 8 and IE 27 are both src_addr, so the key repeats, and the unfilled
    family arrives as zeros that must not displace the filled one.
    """
    fields = [(8, 4), (27, 16), (12, 4), (28, 16), (7, 2)]
    v4 = (bytes([192, 0, 2, 1]) + bytes(16) + bytes([198, 51, 100, 7])
          + bytes(16) + struct.pack("!H", 443))
    v6 = (bytes(4) + bytes(range(1, 17)) + bytes(4) + bytes(range(17, 33))
          + struct.pack("!H", 53))
    return [p.ipfix([p.data_template(600, fields), p.data_set(600, v4 + v6)]),
            p.v9([p.v9_data_template(601, fields), p.data_set(601, v6 + v4)])]


def seed_messages():
    """Well-formed messages of every shape above, in both versions."""
    messages = list(fuzz.seed_corpus())
    for tid, fields in enumerate(SHAPES.values(), start=700):
        body = record_set(fields)
        messages.append(p.ipfix([p.data_template(tid, fields),
                                 p.data_set(tid, body)]))
        messages.append(p.v9([p.v9_data_template(tid + 100, fields),
                              p.data_set(tid + 100, body)]))
    messages.extend(dual_stack_messages())
    # Trailing padding shorter than a record, which both paths must treat as
    # padding rather than as one more short record.
    messages.append(p.ipfix([p.data_template(800, p.FLOW_FIELDS),
                             p.data_set(800, record_set(p.FLOW_FIELDS)
                                        + bytes(3))]))
    # Two data sets for one template in one message.
    messages.append(p.ipfix([p.data_template(801, p.FLOW_FIELDS),
                             p.data_set(801, record_set(p.FLOW_FIELDS, 2)),
                             p.data_set(801, record_set(p.FLOW_FIELDS, 4))]))
    # A variable-length template, which is never compiled: both paths walk it,
    # and it has to coexist with compiled ones in the same store.
    varlen = p.FLOW_FIELDS + [(82, 0xFFFF)]
    messages.append(p.ipfix([p.data_template(802, varlen),
                             p.data_set(802, p.flow_payload() + b"\x03abc")]))
    return [bytes(message) for message in messages]


def mutated_messages(seed=20260911):
    """The fuzzer's own mutations, made reproducible.

    tools/fuzz.py draws some of its garbage from os.urandom, which is right
    for a fuzzer and wrong for a test. Routing it through the seeded generator
    makes this corpus the same on every run and on every machine.
    """
    rng = random.Random(seed)
    seeds = seed_messages()
    with mock.patch.object(fuzz.os, "urandom", rng.randbytes):
        return [fuzz.mutate(rng, rng.choice(seeds)) for _ in range(MUTATIONS)]


class BothPaths(unittest.TestCase):
    """Every corpus decoded twice, once per path, and compared throughout."""

    def assert_same(self, datagrams):
        compiled, walked = Decoder(), Decoder()
        walked.templates._compile = False
        for n, data in enumerate(datagrams):
            a = compiled.decode(data, "10.0.0.1")
            b = walked.decode(data, "10.0.0.1")
            where = f"datagram {n}: {data.hex()}"
            self.assertEqual(a, b, where)
            self.assertEqual(compiled.take_events(), walked.take_events(), where)
        # Counters too: a compiled path that decoded the same records but
        # miscounted a deferred or truncated set would still be wrong.
        self.assertEqual(compiled.stats, walked.stats)
        return compiled, walked

    def test_the_comparison_is_not_vacuous(self):
        # If nothing compiled, every assertion below would pass by comparing
        # the walk with itself.
        compiled, walked = self.assert_same(seed_messages())
        plans = [entry[2] for entry in compiled.templates.templates.values()]
        self.assertTrue(any(plan is not None for plan in plans))
        self.assertTrue(all(entry[2] is None
                            for entry in walked.templates.templates.values()))

    def test_every_seed_message(self):
        self.assert_same(seed_messages())

    def test_every_prefix_of_every_seed_message(self):
        # A cut can land anywhere: mid-header, mid-template, mid-record, or on
        # a record boundary, where the compiled path's arithmetic is tested.
        self.assert_same([message[:cut] for message in seed_messages()
                          for cut in range(len(message) + 1)])

    def test_the_fuzz_corpus(self):
        self.assert_same(mutated_messages())


class WhatCompiles(unittest.TestCase):
    """The compiler's refusals, each of which keeps a template on the walk."""

    def fields(self, pairs, ipfix=True):
        store = TemplateStore()
        msg = (p.ipfix([p.data_template(400, pairs)]) if ipfix
               else p.v9([p.v9_data_template(400, pairs)]))
        parse_v9_or_ipfix(msg, "10.0.0.1", store)
        return store.get("10.0.0.1", 0, 400)[0]

    def test_a_fixed_length_template_compiles(self):
        size, _read = compile_template(self.fields(p.FLOW_FIELDS))
        self.assertEqual(size, sum(length for _eid, length in p.FLOW_FIELDS))

    def test_a_variable_length_field_keeps_the_walk(self):
        self.assertIsNone(compile_template(
            self.fields(p.FLOW_FIELDS + [(82, 0xFFFF)])))

    def test_a_template_of_no_bytes_keeps_the_walk(self):
        # A reader that advanced by zero would never leave the set.
        self.assertIsNone(compile_template(self.fields([(7, 0), (11, 0)])))

    def test_a_layout_in_some_other_shape_is_declined_not_raised(self):
        # TemplateStore.put is public and stores what it is given.
        self.assertIsNone(compile_template(p.FLOW_FIELDS))
        TemplateStore().put("10.0.0.1", 0, 400, p.FLOW_FIELDS)

    def test_a_resend_reuses_the_compiled_reader(self):
        store = TemplateStore()
        fields = self.fields(p.FLOW_FIELDS)
        store.put("10.0.0.1", 0, 400, fields)
        first = store.templates[("10.0.0.1", 0, 400)][2]
        self.assertFalse(store.put("10.0.0.1", 0, 400, list(fields)))
        self.assertIs(store.templates[("10.0.0.1", 0, 400)][2], first)

    def test_a_redefinition_is_recompiled_and_still_reported(self):
        store = TemplateStore()
        store.put("10.0.0.1", 0, 400, self.fields(p.FLOW_FIELDS))
        wider = self.fields(p.FLOW_FIELDS + [(10, 4)])
        self.assertTrue(store.put("10.0.0.1", 0, 400, wider))
        size, _read = store.templates[("10.0.0.1", 0, 400)][2]
        self.assertEqual(size, 21 + 4)

    def test_get_still_answers_in_two_values(self):
        store = TemplateStore()
        store.put("10.0.0.1", 0, 400, self.fields(p.FLOW_FIELDS), options=True)
        fields, is_options = store.get("10.0.0.1", 0, 400)
        self.assertTrue(is_options)
        self.assertEqual(len(fields), len(p.FLOW_FIELDS))

    def test_the_largest_template_a_message_can_carry(self):
        # As many fields of 65,534 bytes as fit in one message beside a small
        # data set, which is about 16,000: a format string far longer than any
        # real exporter's, and a record of about a gigabyte. Compiling it must
        # neither raise nor stall, and a data set that cannot hold one record
        # must yield none, on both paths.
        data_set = p.data_set(400, bytes(1000))
        count = (0xFFFF - 16 - 8 - len(data_set)) // 4
        fields = [(9999, 0xFFFE)] * count
        spec = b"".join(struct.pack("!HH", eid, length)
                        for eid, length in fields)
        body = struct.pack("!HH", 400, count) + spec
        template = struct.pack("!HH", 2, 4 + len(body)) + body
        for compile_it in (True, False):
            with self.subTest(compiled=compile_it):
                decoder = Decoder()
                decoder.templates._compile = compile_it
                message = decoder.decode(p.ipfix([template, data_set]),
                                         "10.0.0.1")
                self.assertEqual(message.flows, [])
                self.assertEqual(decoder.stats["templates_new"], 1)


if __name__ == "__main__":
    unittest.main()
