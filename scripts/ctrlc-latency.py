#!/usr/bin/env python3
"""Measure Ctrl-C-cancels-a-running-command latency against a live box.

Starts a long remote command, waits until it is definitely running, sends a real
SIGINT, and times two different things:

  prompt back  - the shell redraws its prompt
  shell usable - a command typed immediately afterwards actually completes

The second is the one that matters. With MaxRunspaces=1 a next command can queue
behind a still-dying pipeline, so a prompt that returns early can still feel
wedged; measuring only the prompt would hide that.

Repeat runs matter: cancel latency is uniform(0, poll-cap) + RTT because the
terminate Signal must wait out the running command's in-flight Receive, so one
sample tells you almost nothing. Set WSMANCER_POLL_SECONDS to measure the
trade-off.

Usage: ctrlc-latency.py <host> <user> <realm> <password> [samples] [tracefile]
"""
import os, pty, select, struct, subprocess, sys, termios, fcntl, time, re, statistics

if len(sys.argv) < 5:
    sys.exit(__doc__)
HOST, USER, REALM, PASS = sys.argv[1:5]
SAMPLES = int(sys.argv[5]) if len(sys.argv) > 5 else 5
TRACE = sys.argv[6] if len(sys.argv) > 6 else None

BIN = os.path.join(os.path.dirname(os.path.abspath(__file__)), "wsmancer")
if not os.path.exists(BIN):
    BIN = "./wsmancer"
CMD = [BIN, "-i", HOST, "-u", USER, "-r", REALM, "-p", PASS]

ESC_RE = re.compile(rb'\x1b\[[0-9;?]*[a-zA-Z]|\x1b[=>]|\r')
DSR = re.compile(rb'\x1b\[6n')          # the editor's cursor-position query
PROMPT = r"PS [^\n]*> "


class Term:
    def __init__(self, tracefile=None):
        self.master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 50, 120, 0, 0))
        # Cancel latency is editor-independent, but both read loops below have to
        # answer the editor's DSR (ESC[6n) cursor query: a bare PTY has nothing to
        # answer it, so the reader blocks and every sample looks like an infinite
        # hang -- exactly the thing being measured. See docs/verification.md's DSR trap.
        env = dict(os.environ, TERM="xterm-256color")
        if tracefile:
            env["NTLMSEAL_DEBUG"] = "1"
            env["PSRP_DEBUG"] = "1"
            self.trace = open(tracefile, "wb")
            err = self.trace
        else:
            self.trace = None
            err = slave
        self.p = subprocess.Popen(CMD, stdin=slave, stdout=slave, stderr=err,
                                  env=env, close_fds=True)
        os.close(slave)
        self.buf = b""

    def drain(self, timeout=0.4):
        end = time.time() + timeout
        while time.time() < end:
            r, _, _ = select.select([self.master], [], [], 0.02)
            if r:
                try:
                    c = os.read(self.master, 65536)
                except OSError:
                    break
                if not c:
                    break
                self.buf += c
                if DSR.search(c):
                    os.write(self.master, b'\x1b[24;1R')
                end = time.time() + timeout
        return self.buf

    def expect(self, pat, timeout=60.0, tick=0.02):
        """Poll frequently so the returned timestamp is a real latency, not a
        quantum of the drain timeout."""
        end = time.time() + timeout
        while time.time() < end:
            r, _, _ = select.select([self.master], [], [], tick)
            if r:
                try:
                    c = os.read(self.master, 65536)
                except OSError:
                    return None
                if c:
                    self.buf += c
                    if DSR.search(c):
                        os.write(self.master, b'\x1b[24;1R')
            if re.search(pat, self.visible()):
                return time.time()
        return None

    def send(self, data, settle=0.3):
        os.write(self.master, data if isinstance(data, bytes) else data.encode())
        time.sleep(settle)

    def clear(self):
        self.drain(0.2)
        self.buf = b""

    def visible(self):
        return ESC_RE.sub(b'', self.buf).decode("utf8", "replace")

    def close(self):
        try:
            self.p.kill()
        except Exception:
            pass
        if self.trace:
            self.trace.close()


def main():
    t = Term(TRACE)
    print(f"connecting to {HOST} ...", flush=True)
    if not t.expect(PROMPT, timeout=60):
        print("FAIL: never got a prompt.\n--- buffer ---")
        print(t.visible()[-3000:])
        t.close()
        sys.exit(1)
    print("connected.\n", flush=True)

    lat = []
    for i in range(1, SAMPLES + 1):
        t.clear()
        # A long remote command so the cancel always lands mid-run.
        t.send("Start-Sleep -Seconds 60\r", 0.2)
        # Let it get properly under way, and vary the offset so the SIGINT lands
        # at a different point within the receive poll each time.
        time.sleep(2.0 + (i % 5) * 0.9)
        t.clear()

        t0 = time.time()
        os.kill(t.p.pid, 2)  # real SIGINT (see pty-test.py: no controlling tty here)

        hit = t.expect(PROMPT, timeout=90)
        if hit is None:
            print(f"  sample {i}: TIMEOUT (>90s), prompt never returned")
            print(t.visible()[-2000:])
            break
        d_prompt = hit - t0

        # The prompt returning is cosmetic. What the operator actually feels is
        # when the shell is USABLE again, with MaxRunspaces=1 the next command
        # queues behind the still-dying pipeline. Type immediately (no settle)
        # and time until its output lands.
        t.clear()
        os.write(t.master, b"echo ALIVE-%d\r" % i)
        ready = t.expect(r"ALIVE-%d" % i, timeout=90)
        if ready is None:
            print(f"  sample {i}: session did NOT survive the cancel")
            print(t.visible()[-2000:])
            break
        d_ready = ready - t0
        lat.append((d_prompt, d_ready))
        print(f"  sample {i}: prompt {d_prompt:6.2f}s   usable {d_ready:6.2f}s", flush=True)
        t.expect(PROMPT, timeout=30)

    t.close()

    if lat:
        for label, idx in (("prompt back", 0), ("shell usable", 1)):
            xs = [x[idx] for x in lat]
            print(f"\n=== Ctrl-C latency: {label} (n={len(xs)}) ===")
            print(f"  min={min(xs):.2f}s  median={statistics.median(xs):.2f}s  "
                  f"mean={statistics.mean(xs):.2f}s  max={max(xs):.2f}s")


main()
