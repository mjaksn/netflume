"""The benchmark harness's environment check, which decides a warning.

`tools/bench.py` records the environment a measurement was taken in and warns
when the baseline came from somewhere else, because throughput is not portable
between machines or interpreters. That recorded environment also carries the
netflume version, and the version is the one key a baseline is *meant* to
differ on: holding a later release against a committed baseline is the whole
reason for committing one.

Checked alongside the rest, it put the warning on every run after a version
bump, announcing that the percentages compared two environments at exactly the
moment they compared two versions of the code on one runner. A warning that
fires when nothing is wrong is one people stop reading, so both directions are
held here: the version alone must stay silent, and a real difference must
still speak up even when the version moved too.

The harness is not part of the package and nothing else covers it. It is
checked here because the committed baseline made this reachable.
"""

import importlib.util
import io
import json
import os
import unittest
from contextlib import redirect_stdout

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

_spec = importlib.util.spec_from_file_location(
    "netflume_bench_harness", os.path.join(ROOT, "tools", "bench.py"))
bench = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bench)

BASELINE = os.path.join(ROOT, "tools", "bench-baseline.json")


def warning_for(now, was):
    """Whatever ``compare_environments`` prints, which is usually nothing."""
    out = io.StringIO()
    with redirect_stdout(out):
        bench.compare_environments(now, was)
    return out.getvalue()


class CompareEnvironments(unittest.TestCase):
    def setUp(self):
        # The shape of what the runner actually recorded.
        self.was = {
            "python": "3.12.14",
            "implementation": "CPython",
            "system": "Linux",
            "machine": "x86_64",
            bench.VERSION_KEY: "0.4.0",
        }

    def test_the_same_environment_says_nothing(self):
        self.assertEqual(warning_for(dict(self.was), self.was), "")

    def test_a_version_bump_alone_says_nothing(self):
        # What every run on main hits once the release after the baseline is
        # tagged: same runner, same interpreter, later netflume.
        now = dict(self.was, **{bench.VERSION_KEY: "0.5.0"})
        self.assertEqual(warning_for(now, self.was), "")

    def test_another_machine_warns(self):
        now = dict(self.was, system="Windows", machine="AMD64")
        warning = warning_for(now, self.was)
        self.assertIn("taken elsewhere", warning)
        self.assertIn("Linux then, Windows now", warning)
        self.assertIn("x86_64 then, AMD64 now", warning)

    def test_another_interpreter_warns(self):
        now = dict(self.was, python="3.13.0", implementation="PyPy")
        warning = warning_for(now, self.was)
        self.assertIn("3.12.14 then, 3.13.0 now", warning)
        self.assertIn("CPython then, PyPy now", warning)

    def test_a_moved_version_does_not_mask_a_real_difference(self):
        # Skipping the version must not turn into skipping the check.
        now = dict(self.was, system="Windows")
        now[bench.VERSION_KEY] = "0.5.0"
        warning = warning_for(now, self.was)
        self.assertIn("Linux then, Windows now", warning)
        self.assertNotIn(bench.VERSION_KEY, warning)

    def test_a_missing_key_counts_as_drift(self):
        # A baseline recording something this build no longer reports is not
        # comparable either, and the absence should be visible.
        now = {k: v for k, v in self.was.items() if k != "machine"}
        self.assertIn("x86_64 then, None now", warning_for(now, self.was))


class RecordedEnvironment(unittest.TestCase):
    def test_the_version_is_recorded_even_though_it_is_not_compared(self):
        # It is how a baseline says which release produced its numbers.
        self.assertIn(bench.VERSION_KEY, bench.environment())

    def test_every_recorded_key_but_the_version_is_compared(self):
        was = bench.environment()
        for key in was:
            if key == bench.VERSION_KEY:
                continue
            with self.subTest(key=key):
                now = dict(was, **{key: "something else"})
                self.assertIn(key, warning_for(now, was))


class CommittedBaseline(unittest.TestCase):
    """The file the Bench workflow compares against, held to its shape.

    It is written by a runner and committed verbatim, so what can go wrong is
    a hand edit or a truncated download rather than a logic error.
    """

    def setUp(self):
        if not os.path.exists(BASELINE):
            self.skipTest("no committed baseline yet")
        with open(BASELINE, encoding="utf-8") as fh:
            self.baseline = json.load(fh)

    def test_it_records_the_environment_it_was_taken_in(self):
        recorded = self.baseline.get("environment", {})
        self.assertEqual(set(recorded), set(bench.environment()))

    def test_it_covers_every_case_the_harness_measures(self):
        measured = {name for name, _, _, _ in bench.build_cases()}
        self.assertEqual(set(self.baseline.get("cases", {})), measured)

    def test_every_case_carries_a_rate_to_compare_against(self):
        for name, entry in self.baseline["cases"].items():
            with self.subTest(case=name):
                self.assertGreater(entry.get("records_per_second", 0), 0)


if __name__ == "__main__":
    unittest.main()
