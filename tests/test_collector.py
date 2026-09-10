"""The socket layer, driven by a real UDP socket on the loopback.

Nothing here is monkeypatched: the collector binds 127.0.0.1 on a port the
kernel picks, and a second socket sends it synthetic exports. That exercises
the timeout and non-blocking paths for real, which a fake socket cannot.
"""

import socket
import struct
import threading
import time
import unittest

from netflume import Collector, Decoder, Flow

from . import packets as p


class CollectorTestCase(unittest.TestCase):
    def setUp(self):
        # Port 0: the kernel picks a free one, so the suite never collides
        # with a real collector or with a parallel run of itself.
        self.collector = Collector(port=0, bind="127.0.0.1", timeout=0.25)
        self.addCleanup(self.collector.close)
        self.sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.addCleanup(self.sender.close)

    def send(self, data):
        self.sender.sendto(data, self.collector.address)

    def feed(self, *datagrams, timeout=5.0):
        """Send each datagram only once the one before it has been received.

        Not politeness: the loopback stack on the machine this was written on
        holds one queued UDP datagram and drops the rest, which was verified
        with a plain socket and no netflume involved. Firing several and then
        reading would test that quirk rather than this code. Pacing off the
        collector's own packet counter is deterministic either way, and on a
        normal stack it simply never waits.
        """
        def run():
            for data in datagrams:
                before = self.collector.stats["packets"]
                self.sender.sendto(data, self.collector.address)
                deadline = time.monotonic() + timeout
                while (self.collector.stats["packets"] == before
                       and time.monotonic() < deadline):
                    time.sleep(0.002)

        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        self.addCleanup(thread.join, timeout)
        return thread

    def feed_flow(self):
        """A template then a flow, as two datagrams, as an exporter sends them."""
        return self.feed(
            p.ipfix([p.data_template(400, p.TIMED_FLOW_FIELDS)]),
            p.ipfix([p.data_set(400, p.timed_flow_payload())], seq=1))


class Binding(CollectorTestCase):
    def test_it_binds_and_reports_where(self):
        host, port = self.collector.address
        self.assertEqual(host, "127.0.0.1")
        self.assertGreater(port, 0)

    def test_a_port_already_in_use_fails_at_construction(self):
        # Not at first read, when the caller has stopped watching for it.
        busy = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        busy.bind(("127.0.0.1", 0))
        self.addCleanup(busy.close)
        with self.assertRaises(OSError):
            Collector(port=busy.getsockname()[1], bind="127.0.0.1",
                      reuse_address=False)

    def test_it_exposes_a_descriptor_for_a_callers_own_loop(self):
        import selectors
        self.send(p.v5_message(count=1))
        sel = selectors.DefaultSelector()
        sel.register(self.collector, selectors.EVENT_READ)
        try:
            self.assertTrue(sel.select(2.0))
        finally:
            sel.close()

    def test_an_existing_socket_can_be_supplied(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        collector = Collector(sock=sock)
        self.addCleanup(collector.close)
        self.assertEqual(collector.address[0], "127.0.0.1")


class Polling(CollectorTestCase):
    def test_polling_an_idle_socket_returns_none_at_once(self):
        started = time.monotonic()
        self.assertIsNone(self.collector.poll(timeout=0))
        self.assertLess(time.monotonic() - started, 0.5)

    def test_a_timeout_is_honoured_and_bounded(self):
        started = time.monotonic()
        self.assertIsNone(self.collector.poll(timeout=0.2))
        elapsed = time.monotonic() - started
        self.assertGreaterEqual(elapsed, 0.15)
        self.assertLess(elapsed, 2.0)

    def test_a_datagram_is_decoded(self):
        self.send(p.v5_message(count=2))
        message = self.collector.poll(timeout=2.0)
        self.assertIsNotNone(message)
        self.assertEqual(message.version, 5)
        self.assertEqual(len(message.flows), 2)

    def test_the_exporter_is_taken_from_the_source_address(self):
        self.send(p.v5_message(count=1))
        message = self.collector.poll(timeout=2.0)
        self.assertEqual(message.exporter, "127.0.0.1")

    def test_an_undecodable_datagram_polls_as_none_and_is_counted(self):
        self.send(b"\x00")
        self.assertIsNone(self.collector.poll(timeout=2.0))
        self.assertEqual(self.collector.stats["packets"], 1)
        self.assertEqual(self.collector.stats["malformed"], 1)

    def test_polling_a_closed_collector_is_an_error_not_a_hang(self):
        self.collector.close()
        with self.assertRaises(ValueError):
            self.collector.poll(timeout=0)


class Iteration(CollectorTestCase):
    def test_iterating_yields_record_and_header_pairs(self):
        self.feed_flow()
        for rec, hdr in self.collector:
            self.assertEqual(rec["dst_addr"], "8.8.8.8")
            self.assertEqual(hdr["version"], 10)
            break

    def test_the_typed_iterator_yields_flows(self):
        self.feed_flow()
        for flow in self.collector.flows():
            self.assertIsInstance(flow, Flow)
            self.assertEqual(flow.dst_addr, "8.8.8.8")
            self.assertEqual(flow.start, 1700000000.0)
            break

    def test_the_message_iterator_yields_whole_messages(self):
        self.feed_flow()
        seen = []
        for message in self.collector.messages():
            seen.append(message)
            if len(seen) == 2:
                break
        self.assertEqual(seen[0].flows, [], "the template datagram")
        self.assertEqual(len(seen[1].flows), 1)
        self.assertEqual(seen[1].sequence, 1)

    def test_a_template_datagram_yields_no_flows_but_does_not_stall(self):
        self.feed(p.ipfix([p.data_template(400, p.FLOW_FIELDS)]),
                  p.ipfix([p.data_set(400, p.flow_payload())]))
        count = 0
        for _rec, _hdr in self.collector:
            count += 1
            break
        self.assertEqual(count, 1)

    def test_several_flows_in_one_datagram_are_yielded_one_at_a_time(self):
        self.send(p.v5_message(count=3))
        seen = []
        for rec, _hdr in self.collector:
            seen.append(rec)
            if len(seen) == 3:
                break
        self.assertEqual(len(seen), 3)
        self.assertEqual({r["src_addr"] for r in seen},
                         {"192.168.1.10", "192.168.1.11", "192.168.1.12"})


class Shutdown(CollectorTestCase):
    def test_stop_ends_an_iteration_from_another_thread(self):
        # The point of stop(): a daemon has to come down on a signal without
        # waiting for a flow that may never arrive on a quiet network.
        collector = Collector(port=0, bind="127.0.0.1", timeout=30.0)
        self.addCleanup(collector.close)

        finished = threading.Event()

        def drain():
            for _ in collector:
                pass
            finished.set()

        thread = threading.Thread(target=drain, daemon=True)
        thread.start()
        time.sleep(0.1)
        collector.stop()
        self.assertTrue(finished.wait(5.0),
                        "stop() did not interrupt a 30s blocking wait")

    def test_a_stopped_collector_can_still_be_polled(self):
        self.collector.stop()
        self.send(p.v5_message(count=1))
        self.assertIsNotNone(self.collector.poll(timeout=2.0))

    def test_the_context_manager_closes_the_socket(self):
        with Collector(port=0, bind="127.0.0.1") as collector:
            port = collector.address[1]
        self.assertTrue(collector._closed)
        # The port is free again: binding it without SO_REUSEADDR must work.
        again = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        again.bind(("127.0.0.1", port))
        again.close()

    def test_close_is_idempotent(self):
        self.collector.close()
        self.collector.close()


class SharedState(CollectorTestCase):
    def test_a_decoder_can_be_supplied_and_keeps_its_templates(self):
        decoder = Decoder()
        decoder.decode(p.ipfix([p.data_template(400, p.FLOW_FIELDS)]),
                       "127.0.0.1")
        collector = Collector(port=0, bind="127.0.0.1", timeout=0.25,
                              decoder=decoder)
        self.addCleanup(collector.close)
        self.sender.sendto(p.ipfix([p.data_set(400, p.flow_payload())]),
                           collector.address)
        message = collector.poll(timeout=2.0)
        self.assertEqual(len(message.flows), 1)

    def test_stats_are_the_decoders_stats(self):
        self.assertIs(self.collector.stats, self.collector.decoder.stats)

    def test_events_reach_the_caller_through_the_decoder(self):
        self.send(struct.pack("!HH", 3, 0))
        self.collector.poll(timeout=2.0)
        events = self.collector.decoder.take_events()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].reason, "unsupported")


class DualStack(unittest.TestCase):
    """One socket serving both families, with one key per exporter.

    The default bind is every interface on both families, so an IPv4 exporter
    arrives over the v6 socket in its mapped spelling and has to reach the
    tables as a dotted quad. Skipped rather than failed on a machine with no
    IPv6, which is a property of the host and not of this code.
    """

    def setUp(self):
        collector = Collector(port=0, timeout=0.25)
        self.addCleanup(collector.close)
        if collector.socket.family != socket.AF_INET6:
            self.skipTest("no dual-stack socket on this machine")
        self.collector = collector
        self.port = collector.address[1]

    def send_from(self, family, host, data=None):
        """Send one datagram from `host` and return what the collector made."""
        sender = socket.socket(family, socket.SOCK_DGRAM)
        self.addCleanup(sender.close)
        try:
            sender.sendto(p.v5(1) if data is None else data, (host, self.port))
        except OSError as exc:                  # no loopback for that family
            self.skipTest(f"cannot send from {host}: {exc}")
        message = self.collector.poll(timeout=5.0)
        self.assertIsNotNone(message, f"nothing arrived from {host}")
        return message

    def test_an_ipv4_exporter_reaches_the_dual_stack_socket(self):
        message = self.send_from(socket.AF_INET, "127.0.0.1")
        self.assertEqual(message.header["exporter"], "127.0.0.1")

    def test_an_ipv6_exporter_reaches_it_too(self):
        message = self.send_from(socket.AF_INET6, "::1")
        self.assertEqual(message.header["exporter"], "::1")

    def test_both_families_are_decoded_by_the_one_decoder(self):
        self.send_from(socket.AF_INET, "127.0.0.1")
        self.send_from(socket.AF_INET6, "::1")
        self.assertEqual(self.collector.stats["packets"], 2)
        self.assertEqual(self.collector.stats["v5_msgs"], 2)

    def test_an_ipv4_exporters_templates_are_keyed_by_its_dotted_quad(self):
        # The socket reports ::ffff:127.0.0.1 for this sender. The template
        # store must not, or the exporter is invisible to itself after the
        # collector is restarted onto an IPv4 socket.
        self.send_from(socket.AF_INET, "127.0.0.1",
                       p.ipfix([p.data_template(400, p.TIMED_FLOW_FIELDS)]))
        keys = {key[0] for key in self.collector.decoder.templates.templates}
        self.assertEqual(keys, {"127.0.0.1"})


class BindChoosesTheFamily(unittest.TestCase):
    """What `bind` is decides which socket gets made."""

    def family_for(self, **kwargs):
        with Collector(port=0, timeout=0.25, **kwargs) as collector:
            return collector.socket.family

    def test_the_default_is_dual_stack_where_the_machine_allows_it(self):
        family = self.family_for()
        if family == socket.AF_INET:
            self.skipTest("no IPv6 on this machine, so the fallback took it")
        self.assertEqual(family, socket.AF_INET6)

    def test_the_ipv4_wildcard_still_means_ipv4_alone(self):
        self.assertEqual(self.family_for(bind="0.0.0.0"), socket.AF_INET)

    def test_a_named_ipv4_address_is_ipv4(self):
        self.assertEqual(self.family_for(bind="127.0.0.1"), socket.AF_INET)

    def test_an_ipv6_literal_is_ipv6(self):
        try:
            self.assertEqual(self.family_for(bind="::1"), socket.AF_INET6)
        except OSError as exc:
            self.skipTest(f"no IPv6 loopback to bind: {exc}")


if __name__ == "__main__":
    unittest.main()
