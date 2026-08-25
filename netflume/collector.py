"""Binding the socket and handing back flows.

:class:`Collector` is a UDP socket, a :class:`~netflume.decoder.Decoder`
and three ways to get at what arrives:

* ``for rec, hdr in collector:`` gives plain dicts, the cheapest form
* ``for flow in collector.flows():`` gives typed objects, built on demand
* ``message = collector.poll(timeout)`` gives one datagram, or None, for a
  caller who owns the event loop

It prints nothing, exits nothing, and reads no arguments. Everything it would
otherwise have to say arrives as an event from
:meth:`~netflume.decoder.Decoder.take_events` or on the
``netflume`` logger.
"""

import errno
import logging
import selectors
import socket
import time

from .decoder import Decoder

__all__ = ["Collector", "DEFAULT_PORT", "DEFAULT_RCVBUF"]

log = logging.getLogger(__name__)

#: The port every NetFlow exporter defaults to. Not registered to anything and
#: not privileged, so a daemon need not run as root.
DEFAULT_PORT = 2055

#: 4 MB of kernel receive buffer. UDP has no backpressure: a buffer that fills
#: while this process is busy drops datagrams silently and the only trace is a
#: sequence gap. Ask for more than the system default, and do not fail if the
#: system says no.
DEFAULT_RCVBUF = 4 * 1024 * 1024

#: The largest datagram to accept. A NetFlow export never approaches this;
#: it is simply the largest a UDP payload can be.
MAX_DATAGRAM = 65535


class Collector:
    """A bound UDP socket that yields decoded NetFlow.

    ::

        with Collector(port=2055) as collector:
            for rec, hdr in collector:
                store(rec, hdr)

    The socket is bound in the constructor, so a port already in use raises
    OSError there rather than at first read. Use ``with``, or call
    :meth:`close`, so the socket is released promptly; the alternative is a
    port left held until the garbage collector gets round to it.

    Iteration is endless by design: a collector with nothing to report is a
    quiet network, not a finished job. Break out of the loop, or call
    :meth:`stop` from a signal handler or another thread.
    """

    def __init__(self, port=DEFAULT_PORT, bind="0.0.0.0", decoder=None,
                 timeout=1.0, rcvbuf=DEFAULT_RCVBUF, reuse_address=True,
                 sock=None):
        """Bind and get ready to receive.

        port, bind    where to listen. "0.0.0.0" is every IPv4 interface; name
                      one interface if the machine is multi-homed and only one
                      of them faces the exporters.
        decoder       an existing Decoder, if you want to share template state
                      with something else or to have turned tracking off.
        timeout       how long the blocking reads inside iteration wait before
                      coming up for air. It bounds how long :meth:`stop` takes
                      to be noticed; it is not a deadline on receiving.
        rcvbuf        kernel receive buffer to request, or None to leave the
                      system default alone.
        reuse_address set SO_REUSEADDR before binding. Default True, which lets
                      a restart of this process take the port back immediately
                      instead of waiting for the old socket to clear. The cost
                      is that on UDP it also lets a *second* process bind the
                      same port, and then only one of them receives: a
                      collector that looks bound and healthy while another
                      process quietly takes its traffic. Pass False to make
                      that clash raise OSError here instead of going silent.
        sock          an already-bound socket to use instead of making one,
                      which is how a test drives this without a real exporter.
        """
        self.decoder = decoder if decoder is not None else Decoder()
        self.timeout = timeout
        self._closed = False
        self._stopping = False

        if sock is None:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            if reuse_address:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if rcvbuf:
                try:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, rcvbuf)
                except OSError as exc:
                    log.debug("could not set SO_RCVBUF to %d: %s", rcvbuf, exc)
            try:
                sock.bind((bind, port))
            except OSError:
                sock.close()
                raise
        self.socket = sock
        self.socket.setblocking(False)

        # A socketpair rather than a pipe: select() on Windows takes sockets
        # and nothing else, and stop() has to be able to interrupt a wait from
        # another thread or a signal handler.
        self._waker_r, self._waker_w = socket.socketpair()
        self._waker_r.setblocking(False)
        self._selector = selectors.DefaultSelector()
        self._selector.register(self.socket, selectors.EVENT_READ)
        self._selector.register(self._waker_r, selectors.EVENT_READ)

        log.info("listening for NetFlow/IPFIX on %s", self.address)

    # == properties ==========================================================

    @property
    def address(self):
        """The (host, port) actually bound, which matters when port was 0."""
        return self.socket.getsockname()

    @property
    def stats(self):
        """The decoder's running counters. See the README for the keys."""
        return self.decoder.stats

    def fileno(self):
        """The socket's descriptor, so this can go straight into a caller's
        own ``selectors`` or ``asyncio`` loop. Pair it with
        ``poll(timeout=0)``, which never blocks."""
        return self.socket.fileno()

    # == receiving ===========================================================

    def poll(self, timeout=0):
        """Wait up to `timeout` seconds for one datagram and decode it.

        Returns a :class:`~netflume.decoder.Message`, or None if
        nothing arrived in time or what arrived would not decode. The two are
        deliberately not distinguished here: neither is an error, and a caller
        who cares can read :meth:`~netflume.decoder.Decoder.take_events`.

        ``timeout=0`` polls without blocking, ``timeout=None`` waits
        indefinitely.

        Raises ValueError once :meth:`close` has been called. Iteration and
        :meth:`flows` stop quietly instead, because a loop that has been shut
        down is finishing normally, whereas asking a closed collector for one
        more datagram is a mistake worth hearing about.
        """
        if self._closed:
            raise ValueError("collector is closed")
        data, addr = self._receive(timeout, honour_stop=False)
        if data is None:
            return None
        return self.decoder.decode(data, addr[0])

    def messages(self, timeout=None):
        """Yield one :class:`~netflume.decoder.Message` per datagram.

        Endless, and skips datagrams that do not decode. Use this rather than
        :meth:`__iter__` when the sequence number, the export time or the
        option records matter, since those belong to a message, not a flow.
        """
        if timeout is None:
            timeout = self.timeout
        while not self._stopping and not self._closed:
            data, addr = self._receive(timeout)
            if data is None:
                continue
            message = self.decoder.decode(data, addr[0])
            if message is not None:
                yield message

    def __iter__(self):
        """Yield (record, header) for every flow, as plain dicts.

        The header comes along because a v5 or v9 record cannot be timestamped
        without it. This is the cheapest shape: no objects are built beyond
        what the parser already made.
        """
        for message in self.messages():
            header = message.header
            for rec in message.flows:
                yield rec, header

    def flows(self, now=None):
        """Yield a :class:`~netflume.flow.Flow` for every flow.

        The typed shape: aliases resolved, timestamp derived, sampling rate
        attached, and the original dict still on ``flow.raw``.
        """
        for message in self.messages():
            for flow in message.typed_flows(now=now):
                yield flow

    # == shutting down =======================================================

    def stop(self):
        """Ask the iterators to finish. Safe from a signal handler or thread.

        Returns immediately; the loop stops after at most one `timeout`. The
        socket is left open, so a stopped collector can be read again with
        :meth:`poll`. Call :meth:`close` to release it.
        """
        self._stopping = True
        try:
            self._waker_w.send(b"\x00")
        except OSError:
            pass

    def close(self):
        """Release the socket. Idempotent, and implied by leaving a ``with``."""
        if self._closed:
            return
        self._closed = True
        self._stopping = True
        self._selector.close()
        for handle in (self.socket, self._waker_r, self._waker_w):
            try:
                handle.close()
            except OSError:
                pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False

    # == the one place that touches the socket ===============================

    def _receive(self, timeout, honour_stop=True):
        """(data, addr), or (None, None) if nothing was ready in time.

        `honour_stop` is what separates the two callers. An iterator wants a
        stop() to end its wait immediately, however long the timeout was.
        poll() is a single explicit read and answers the question it was
        asked, stopped or not.
        """
        deadline = None if timeout is None else time.monotonic() + timeout
        while True:
            remaining = (None if deadline is None
                         else max(0.0, deadline - time.monotonic()))
            ready = self._selector.select(remaining)
            if not ready:
                return None, None

            woken = False
            for key, _events in ready:
                if key.fileobj is self._waker_r:
                    woken = True
                    try:
                        self._waker_r.recv(4096)   # drain, it carries no data
                    except OSError:
                        pass
                    continue
                try:
                    return self.socket.recvfrom(MAX_DATAGRAM)
                except OSError as exc:
                    if exc.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                        return None, None
                    # WSAECONNRESET: Windows reports an ICMP port-unreachable
                    # caused by an earlier send as an error on the *next* read
                    # of a UDP socket. Nothing is wrong with this socket.
                    if getattr(exc, "winerror", None) == 10054:
                        log.debug("ignoring a stale ICMP error on the socket")
                        return None, None
                    raise

            # Only the wakeup fired. Go round again with whatever time is left,
            # rather than reporting nothing: stop() must not cost the caller a
            # datagram that was already queued behind it.
            if not woken or (honour_stop and self._stopping):
                return None, None
            if deadline is not None and time.monotonic() >= deadline:
                return None, None
