#!/usr/bin/env python3
"""A TCP proxy that breaks connections on command, to study transport recovery.

Sits between wsmancer and the WinRM listener so a connection break can be
triggered at an exact moment (idle, or mid-command) without root or waiting on a
server idle timeout.

Write the kill-file to trigger a break. Its contents choose HOW the connection
dies, and the distinction matters more than it looks:

  (empty)     RST -- the peer actively refuses. The client's blocked read fails
              immediately, the transport re-dials and recovers.
  blackhole   the flow is silently discarded, sockets left open. NOTHING comes
              back and no RST/FIN is ever sent, so a read with no deadline blocks
              in netpoll forever. This is what a dropped VPN, a NAT timeout or a
              firewall discarding the flow actually looks like, and it is the
              case that exposed the missing socket-deadline backstop.

  break-proxy.py <listen_port> <target_host> <target_port> <killfile>
"""
import os, socket, sys, threading, time

LISTEN, THOST, TPORT, KILLFILE = int(sys.argv[1]), sys.argv[2], int(sys.argv[3]), sys.argv[4]

live = []          # (client_sock, server_sock)
lock = threading.Lock()
stats = {"conns": 0, "kills": 0}
blackhole = threading.Event()


def pump(src, dst, tag):
    try:
        while True:
            b = src.recv(65536)
            if not b:
                break
            if blackhole.is_set():
                continue      # swallow it: no forward, no close, no RST
            dst.sendall(b)
    except OSError:
        pass
    finally:
        # In blackhole mode leave both sockets open. Shutting them down would
        # send the client a FIN, which it reports as "unexpected EOF" and
        # recovers from -- the exact opposite of the silent discard we are
        # trying to reproduce. A blackholed path sends nothing, ever.
        if not blackhole.is_set():
            for s in (src, dst):
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass


def handle(cs):
    try:
        ss = socket.create_connection((THOST, TPORT), timeout=15)
    except OSError as e:
        print(f"[proxy] upstream connect failed: {e}", flush=True)
        cs.close()
        return
    with lock:
        live.append((cs, ss))
        stats["conns"] += 1
        n = stats["conns"]
    print(f"[proxy] conn #{n} established", flush=True)
    threading.Thread(target=pump, args=(cs, ss, "c->s"), daemon=True).start()
    pump(ss, cs, "s->c")
    with lock:
        if (cs, ss) in live:
            live.remove((cs, ss))
    print(f"[proxy] conn #{n} closed", flush=True)


def killer():
    """Break connections whenever the kill-file appears, per its contents.

    RST mode uses SO_LINGER 0 so close() sends a reset rather than a clean FIN:
    a graceful shutdown lets the client tear down tidily and does not exercise
    the same path. Blackhole mode closes nothing at all -- it just stops relaying
    forever, which is the only way to reproduce a read that never returns.

    **This kill is not reliable, and a caller must verify it.** Closing a socket
    that another thread is blocked in is undefined in CPython, and measured on
    2026-08-02 it sometimes leaves BOTH ends ESTABLISHED with the relay stopped
    -- silently turning an RST test into a blackhole test. The client then waits
    out its 120s dead-comms backstop, which looks exactly like "the client
    ignored the break" and cost a long investigation before `ss -tan` showed the
    connection had never died.

    Do not try to verify it from in here with fileno(): that was tried and
    reports success in the failing case, because the Python object closes while
    the connection stays up. The workable signals are external -- TCP state via
    `ss`, or the peer re-dialling (which shows up here as a later "conn #N
    established", and in a harness as a second NTLM handshake). See
    docs/verification.md.
    """
    while True:
        if os.path.exists(KILLFILE):
            try:
                mode = open(KILLFILE).read().strip().lower()
            except OSError:
                mode = ""
            os.unlink(KILLFILE)
            stats["kills"] += 1

            if mode == "blackhole":
                blackhole.set()
                print("[proxy] BLACKHOLE engaged: traffic silently discarded, "
                      "no RST/FIN (connections stay open)", flush=True)
                continue

            with lock:
                victims = list(live)
                live.clear()
            for cs, ss in victims:
                for s in (cs, ss):
                    try:
                        s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                                     __import__("struct").pack("ii", 1, 0))
                        s.close()
                    except OSError:
                        pass
            print(f"[proxy] KILLED {len(victims)} connection(s) with RST", flush=True)
        time.sleep(0.05)


threading.Thread(target=killer, daemon=True).start()
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", LISTEN))
srv.listen(8)
print(f"[proxy] 127.0.0.1:{LISTEN} -> {THOST}:{TPORT}, killfile={KILLFILE}", flush=True)
while True:
    cs, _ = srv.accept()
    threading.Thread(target=handle, args=(cs,), daemon=True).start()
