"""Export sequence gaps: find real loss, invent none."""

import unittest

from netflume import MAX_PLAUSIBLE_GAP, RESYNC_AFTER, SEQ_MODULUS, SequenceWatch
from netflume.events import ExportGap


class LearningHowAnExporterCounts(unittest.TestCase):
    def test_a_record_counter_is_learned(self):
        w = SequenceWatch()
        gaps = [w.observe("a", 0, 10, seq, 10) for seq in (0, 10, 20, 30)]
        self.assertEqual(gaps, [0, 0, 0, 0], "learning must report nothing")
        self.assertEqual(w.streams[("a", 0, 10)]["mode"], "records")
        self.assertEqual(w.missed, {})

    def test_a_message_counter_is_learned(self):
        w = SequenceWatch()
        for seq in (7, 8, 9):
            w.observe("b", 0, 9, seq, 5)
        self.assertEqual(w.streams[("b", 0, 9)]["mode"], "messages")
        self.assertEqual(w.missed, {})

    def test_a_v9_exporter_counting_records_raises_no_false_alarm(self):
        # v9 is specified to count messages and widely built to count records.
        # Trusting the version rather than the evidence invents a loss on
        # every single message.
        w = SequenceWatch()
        gaps = [w.observe("c", 0, 9, seq, 25) for seq in (0, 25, 50, 75, 100)]
        self.assertEqual(gaps, [0] * 5)
        self.assertEqual(w.streams[("c", 0, 9)]["mode"], "records")
        self.assertEqual(w.missed, {})

    def test_one_record_per_message_teaches_nothing_and_is_never_judged(self):
        w = SequenceWatch()
        for seq in (1, 2, 3, 4):
            w.observe("d", 0, 9, seq, 1)
        self.assertIsNone(w.streams[("d", 0, 9)]["mode"])
        self.assertEqual(w.missed, {})
        self.assertFalse(w.watched())

    def test_watched_turns_true_once_anything_is_known(self):
        w = SequenceWatch()
        for seq in (0, 10):
            w.observe("a", 0, 10, seq, 10)
        self.assertTrue(w.watched())


class FindingGaps(unittest.TestCase):
    def test_a_skipped_message_is_reported_and_attributed(self):
        w = SequenceWatch()
        for seq in (0, 10, 20, 30):
            w.observe("a", 0, 10, seq, 10)
        self.assertEqual(w.observe("a", 0, 10, 50, 10), 10)
        self.assertEqual(w.missed[("a", 0, 10)], 10)
        self.assertEqual(w.units[("a", 0, 10)], "data records")

    def test_the_stream_resynchronises_after_a_gap(self):
        w = SequenceWatch()
        for seq in (0, 10, 20, 30):
            w.observe("a", 0, 10, seq, 10)
        w.observe("a", 0, 10, 50, 10)
        self.assertEqual(w.observe("a", 0, 10, 60, 10), 0)
        self.assertEqual(w.missed[("a", 0, 10)], 10)

    def test_lost_messages_are_counted_in_messages(self):
        w = SequenceWatch()
        for seq in (7, 8, 9):
            w.observe("b", 0, 9, seq, 5)
        self.assertEqual(w.observe("b", 0, 9, 12, 5), 2)
        self.assertEqual(w.units[("b", 0, 9)], "export messages")

    def test_v5_gaps_are_counted_in_flow_records(self):
        w = SequenceWatch()
        for seq in (0, 10, 20):
            w.observe("n", 0, 5, seq, 10)
        w.observe("n", 0, 5, 40, 10)
        self.assertEqual(w.units[("n", 0, 5)], "flow records")

    def test_ipfix_option_records_count_towards_the_sequence(self):
        # They are data records, and IPFIX counts every data record it sends.
        w = SequenceWatch()
        w.observe("h", 0, 10, 0, 2, 1)
        w.observe("h", 0, 10, 3, 2, 1)
        self.assertEqual(w.streams[("h", 0, 10)]["mode"], "records")
        self.assertEqual(w.missed, {})
        self.assertEqual(w.observe("h", 0, 10, 9, 2, 1), 3)

    def test_v9_option_records_do_not(self):
        w = SequenceWatch()
        w.observe("h9", 0, 9, 0, 2, 1)
        w.observe("h9", 0, 9, 2, 2, 1)
        self.assertEqual(w.streams[("h9", 0, 9)]["mode"], "records")

    def test_a_message_with_no_sequence_number_is_ignored(self):
        self.assertEqual(SequenceWatch().observe("k", 0, 5, None, 3), 0)


class ThingsThatLookLikeLossButAreNot(unittest.TestCase):
    def test_a_repeated_message_is_reordering_not_loss(self):
        w = SequenceWatch()
        for seq in (100, 110, 120):
            w.observe("e", 0, 10, seq, 10)
        self.assertEqual(w.observe("e", 0, 10, 110, 10), 0)
        self.assertEqual(w.backwards, 1)
        # The high-water mark stays put, or the next in-order message would
        # read as a fresh gap.
        self.assertEqual(w.observe("e", 0, 10, 130, 10), 0)
        self.assertEqual(w.missed, {})

    def test_a_counter_restart_is_not_loss(self):
        w = SequenceWatch()
        for seq in (5000, 5010, 5020):
            w.observe("f", 0, 10, seq, 10)
        self.assertEqual(w.observe("f", 0, 10, 0, 10), 0)
        self.assertEqual(w.missed, {})
        self.assertEqual(w.resyncs, 1)

    def test_tracking_continues_from_the_new_base_after_a_restart(self):
        w = SequenceWatch()
        for seq in (5000, 5010, 5020):
            w.observe("f", 0, 10, seq, 10)
        w.observe("f", 0, 10, 0, 10)
        self.assertEqual(w.observe("f", 0, 10, 10, 10), 0)
        self.assertEqual(w.observe("f", 0, 10, 40, 10), 20)

    def test_a_run_of_small_backward_steps_is_still_a_restart(self):
        # The counter began again while it was still low, so each step back
        # sits inside the reordering window. A run of them is not reordering.
        w = SequenceWatch()
        for seq in (500, 510, 520):
            w.observe("r", 0, 10, seq, 10)
        for _ in range(RESYNC_AFTER):
            w.observe("r", 0, 10, 0, 10)
        self.assertEqual(w.resyncs, 1)
        self.assertEqual(w.backwards, RESYNC_AFTER - 1)
        self.assertEqual(w.observe("r", 0, 10, 10, 10), 0)
        self.assertEqual(w.missed, {})

    def test_an_implausibly_large_forward_jump_is_a_restart_too(self):
        w = SequenceWatch()
        for seq in (0, 10, 20):
            w.observe("s", 0, 10, seq, 10)
        self.assertEqual(w.observe("s", 0, 10, MAX_PLAUSIBLE_GAP + 100, 10), 0)
        self.assertEqual(w.resyncs, 1)
        self.assertEqual(w.missed, {})

    def test_the_thirty_two_bit_counter_wraps_without_inventing_a_gap(self):
        w = SequenceWatch()
        top = SEQ_MODULUS - 20
        for seq in (top, top + 10):
            w.observe("g", 0, 10, seq, 10)
        self.assertEqual(w.observe("g", 0, 10, 0, 10), 0)
        self.assertEqual(w.missed, {})

    def test_and_a_real_gap_across_the_wrap_is_still_found(self):
        w = SequenceWatch()
        top = SEQ_MODULUS - 20
        for seq in (top, top + 10):
            w.observe("g", 0, 10, seq, 10)
        w.observe("g", 0, 10, 0, 10)
        self.assertEqual(w.observe("g", 0, 10, 30, 10), 20)


class StreamsAreKeptApart(unittest.TestCase):
    def test_one_exporters_gap_is_not_charged_to_another(self):
        w = SequenceWatch()
        for seq in (0, 10, 20):
            w.observe("i", 0, 10, seq, 10)
            w.observe("j", 0, 10, seq, 10)
        w.observe("i", 0, 10, 40, 10)
        self.assertEqual(w.missed, {("i", 0, 10): 10})

    def test_a_second_observation_domain_is_tracked_separately(self):
        w = SequenceWatch()
        for seq in (0, 10, 20):
            w.observe("i", 0, 10, seq, 10)
        w.observe("i", 0, 10, 40, 10)
        w.observe("i", 7, 10, 999, 10)
        self.assertIn(("i", 7, 10), w.streams)
        self.assertEqual(w.missed, {("i", 0, 10): 10})

    def test_two_streams_on_one_exporter_keep_their_own_mode_and_unit(self):
        w = self._two_streams()
        self.assertEqual(w.streams[("m", 0, 9)]["mode"], "messages")
        self.assertEqual(w.streams[("m", 7, 9)]["mode"], "records")
        self.assertEqual(w.units[("m", 0, 9)], "export messages")
        self.assertEqual(w.units[("m", 7, 9)], "data records")

    def test_losses_are_kept_per_stream_not_summed(self):
        # Adding a count of export messages to a count of data records would
        # produce a number that means nothing at all.
        w = self._two_streams()
        self.assertEqual(w.missed, {("m", 0, 9): 2, ("m", 7, 9): 40})

    @staticmethod
    def _two_streams():
        w = SequenceWatch()
        for seq in (10, 11, 12):
            w.observe("m", 0, 9, seq, 5)          # counts messages
        w.observe("m", 0, 9, 15, 5)               # 2 messages lost
        for seq in (100, 120, 140):
            w.observe("m", 7, 9, seq, 20)         # counts records
        w.observe("m", 7, 9, 200, 20)             # 40 records lost
        return w


class Reporting(unittest.TestCase):
    def test_rows_are_worst_first_and_name_the_stream_when_ambiguous(self):
        w = StreamsAreKeptApart._two_streams()
        rows = w.report()
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0], ("m v9 domain 7", 40, "data records"))
        self.assertEqual(rows[1], ("m v9 domain 0", 2, "export messages"))

    def test_a_single_stream_is_labelled_with_the_bare_address(self):
        w = SequenceWatch()
        for seq in (0, 10, 20):
            w.observe("n", 0, 5, seq, 10)
        w.observe("n", 0, 5, 40, 10)
        self.assertEqual(w.report(), [("n", 10, "flow records")])

    def test_an_exporter_with_no_losses_is_not_reported(self):
        self.assertEqual(SequenceWatch().report(), [])
        self.assertEqual(SequenceWatch().gaps(), [])

    def test_gaps_are_available_as_objects(self):
        w = SequenceWatch()
        for seq in (0, 10, 20):
            w.observe("n", 0, 5, seq, 10)
        w.observe("n", 0, 5, 40, 10)
        gap = w.gaps()[0]
        self.assertIsInstance(gap, ExportGap)
        self.assertEqual((gap.exporter, gap.missed, gap.unit),
                         ("n", 10, "flow records"))


class Events(unittest.TestCase):
    def test_the_first_gap_for_an_exporter_raises_one_event(self):
        w = SequenceWatch()
        for seq in (0, 10, 20):
            w.observe("l", 0, 10, seq, 10)
        w.observe("l", 0, 10, 40, 10)
        w.observe("l", 0, 10, 70, 10)
        events = w.take_events()
        self.assertEqual(len(events), 1, "one heads-up, not one per message")
        self.assertEqual(events[0].missed, 10)
        # Both gaps are still counted, only the announcing is deduplicated.
        self.assertEqual(w.missed[("l", 0, 10)], 30)

    def test_events_are_taken_once(self):
        w = SequenceWatch()
        for seq in (0, 10, 20):
            w.observe("l", 0, 10, seq, 10)
        w.observe("l", 0, 10, 40, 10)
        self.assertEqual(len(w.take_events()), 1)
        self.assertEqual(w.take_events(), [])

    def test_the_event_says_what_was_lost_and_where(self):
        w = SequenceWatch()
        for seq in (0, 10, 20):
            w.observe("10.0.0.1", 0, 10, seq, 10)
        w.observe("10.0.0.1", 0, 10, 40, 10)
        text = str(w.take_events()[0])
        self.assertIn("10.0.0.1", text)
        self.assertIn("10 data records", text)

    def test_it_reaches_the_log_as_well(self):
        w = SequenceWatch()
        for seq in (0, 10, 20):
            w.observe("l", 0, 10, seq, 10)
        with self.assertLogs("netflume.sequence", "WARNING"):
            w.observe("l", 0, 10, 40, 10)

    def test_nothing_is_written_to_stdout_or_stderr(self):
        import contextlib
        import io
        out, err = io.StringIO(), io.StringIO()
        w = SequenceWatch()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            for seq in (0, 10, 20):
                w.observe("l", 0, 10, seq, 10)
            w.observe("l", 0, 10, 40, 10)
        self.assertEqual((out.getvalue(), err.getvalue()), ("", ""))


if __name__ == "__main__":
    unittest.main()
