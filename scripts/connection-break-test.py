#!/usr/bin/env python3
"""Prove what a severed TCP connection does to a live PSRP session.

The transport owns one connection and re-dials transparently when it breaks. The
question that matters is what survives that: this drives wsmancer through a
PTY, routes it via break-proxy.py, and cuts the connection at a chosen moment.

Scenarios:
  idle     break between commands, then run one   -> expect transparent recovery
  running  break during a command's QUIET phase   -> expect that command to
                                                     SURVIVE and complete
  state    plant a variable, a function and a cwd, break, then read them back
           -> expect ALL of them to survive (the runspace is not re-created)
  blackhole  silently drop the connection instead of resetting it (no RST)
           -> expect the read deadline backstop to free the wedged read rather
              than the session hanging forever

`running` expects survival because this shell's output is not streamed: it is
rendered on completion and delivered in one burst, so a break before that has
nothing to destroy and the transport's replay recovers it. A `burst` scenario
aimed at the one window that CAN destroy output was attempted and withdrawn --
see docs/verification.md; it never landed from this harness, and a scenario that
reports "inconclusive" on every run is worse than none.

The `state` scenario is the important one: a recovered connection would be
worthless if the session silently forgot scripts loaded with -s, the functions
`menu` registered, or the working directory.

The behavior under study is editor-independent, but the harness still has to
answer the editor's startup DSR (ESC[6n) cursor query: a bare PTY has nothing to
answer it, the reader blocks, and the artifact looks exactly like the transport
hang this script exists to measure. See docs/verification.md's DSR trap.

Usage:
  scripts/break-proxy.py 15985 <host> 5985 /tmp/KILL &
  scripts/connection-break-test.py <scenario> <proxy_port> <killfile> \
      <user> <realm> <password> [trace]
"""
import os, pty, select, struct, subprocess, sys, termios, fcntl, time, re

if len(sys.argv) < 7:
    sys.exit(__doc__)
SCENARIO, PORT, KILLFILE, USER, REALM, PASS = sys.argv[1:7]
TRACE = sys.argv[7] if len(sys.argv) > 7 else "/dev/null"

BIN = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "wsmancer")
ESC_RE = re.compile(rb'\x1b\[[0-9;?]*[a-zA-Z]|\x1b[=>]|\r')
DSR = re.compile(rb'\x1b\[6n')          # the editor's cursor-position query
PROMPT = r"PS [^\n]*> "

master, slave = pty.openpty()
fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 50, 120, 0, 0))
trace = open(TRACE, "wb")
env = dict(os.environ) | {
    "TERM": "xterm-256color", "NTLMSEAL_DEBUG": "1", "PSRP_DEBUG": "1",
}
p = subprocess.Popen(
    [BIN, "-i", "127.0.0.1", "--port", PORT, "-u", USER, "-r", REALM, "-p", PASS],
    stdin=slave, stdout=slave, stderr=trace, env=env, close_fds=True)
os.close(slave)
buf = b""
results = []


def check(name, ok):
    results.append(bool(ok))
    print(f"  {'PASS' if ok else 'FAIL'}  {name}", flush=True)
    return ok


def visible():
    return ESC_RE.sub(b'', buf).decode("utf8", "replace")


def expect(pat, timeout=60):
    global buf
    end = time.time() + timeout
    while time.time() < end:
        r, _, _ = select.select([master], [], [], 0.05)
        if r:
            try:
                c = os.read(master, 65536)
            except OSError:
                return False
            if c:
                buf += c
                if DSR.search(c):
                    os.write(master, b'\x1b[24;1R')
        if re.search(pat, visible()):
            return True
    return False


def send(s, settle=0.3):
    os.write(master, s.encode())
    time.sleep(settle)


def kill_conn(mode=""):
    with open(KILLFILE, "w") as f:
        f.write(mode)
    print(f">>> broke the connection ({mode or 'RST'})", flush=True)
    time.sleep(1.5)


if not expect(PROMPT):
    print("FATAL: no prompt\n" + visible()[-2000:])
    p.kill()
    sys.exit(1)
print(f"== connected ({SCENARIO}) ==", flush=True)

def sync(tag):
    """Run a command and wait for output only it could produce, then for the
    prompt. Matching anything the prompt itself contains (a backslash, say) would
    return instantly and let the next step type into a still-busy shell."""
    global buf
    buf = b""
    send(f"$s='{tag[:4]}'+'{tag[4:]}'; echo $s\r", 0.3)
    if not expect(tag, 40) or not expect(PROMPT, 30):
        print(f"FATAL: never settled at a prompt ({tag})\n" + visible()[-800:])
        p.kill()
        sys.exit(1)


# Settle first, so the break lands on a genuinely idle session.
sync("SYNCREADY")

if SCENARIO == "idle":
    kill_conn()
    buf = b""
    send("$n='AFTER'+'BREAK'; echo $n\r", 0.3)
    check("session recovers transparently after an idle break",
          expect("AFTERBREAK", 60))

elif SCENARIO == "running":
    # A break during the command's QUIET phase, which is what breaking 3s into a
    # 20s command is.
    #
    # PSRP does not stream this shell's output. The result is rendered remotely
    # (Out-String) and delivered as a single burst when the pipeline completes:
    # measured at the proxy, a 20s command's server->client traffic is ~1800
    # bytes every ~1.05s -- identical for a silent command and one "emitting" 40
    # tokens -- and the tokens all arrive in one final chunk. So every Receive
    # response before completion carries no output, and the seal layer's replay
    # of one costs nothing.
    #
    # Hence the command SURVIVES. Measured 2026-08-02 on Forest, 21/21 across
    # break offsets 1.2s-8s. This assertion used to be the exact opposite, from
    # a much older measurement; see docs/verification.md before changing it back,
    # including for the window where a break DOES destroy output -- which this
    # harness could not be made to hit.
    #
    # The marker is assembled on the target so the terminal echo of the typed
    # line cannot satisfy the match -- only real command output can.
    buf = b""
    send("Start-Sleep -Seconds 20; $m='DONE'+'SLEEP'; echo $m\r", 0.3)
    time.sleep(3)
    kill_conn()
    check("the in-flight command survives a break in its quiet phase",
          expect("DONESLEEP", 60))
    # Anti-vacuity: surviving is only meaningful if the break actually severed a
    # live connection. A kill that hit nothing would produce an untouched
    # session and pass the check above for the wrong reason, which is precisely
    # how four runs of this measurement fooled its author. A re-dial means a
    # second NTLM handshake, so the trace is the witness.
    trace.flush()
    seen = open(TRACE, "rb").read().decode("utf8", "replace") \
        if TRACE != "/dev/null" else ""
    redialled = TRACE == "/dev/null" or seen.count("leg1") >= 2
    check("...and the break was real: the transport re-dialled (>=2 handshakes)",
          redialled)
    if not results[-2] and not redialled:
        # Both checks failing with only ONE handshake is a harness fault, not a
        # product defect, and it cost a long investigation before the cause was
        # pinned. It is the DSR trap wearing a disguise: some read consumed the
        # client's ESC[6n without answering, so the client blocked in
        # GetCursorPos, stopped draining its socket (`ss` shows the peer holding
        # an unread send queue) and could not act on the break at all. Proven by
        # intervention -- swallowing the query fails 4/4, swallowing it and then
        # writing ESC[24;1R anyway passes.
        print("  NOTE  one handshake and no re-dial almost always means THIS "
              "HARNESS ate the client's ESC[6n without answering it: the client "
              "then blocks in GetCursorPos, stops draining its socket, and "
              "cannot act on the break. Check every read path answers the query "
              "-- a read window that ends between a query and its answer "
              "swallows one. See docs/verification.md.")
    buf = b""
    send("$n='AFTER'+'BREAK'; echo $n\r", 0.3)
    if not check("the NEXT command works (session recovered)", expect("AFTERBREAK", 60)):
        if os.environ.get("WSM_DUMP_ON_HANG") and p.poll() is None:
            # SIGQUIT makes the Go runtime dump every goroutine stack to stderr
            # (the trace file), which says exactly where it is stuck.
            print(">>> hung: dumping goroutine stacks via SIGQUIT", flush=True)
            p.send_signal(3)
            time.sleep(2)

elif SCENARIO == "state":
    buf = b""
    send(r"$WSMVAR='PLANTED'; function Get-WsmMarker { 'FUNCALIVE' }; "
         r"cd C:\Windows; $r='PLANT'+'ED-OK'; echo $r" + "\r", 0.3)
    if not expect("PLANTED-OK", 40) or not expect(PROMPT, 30):
        print("FATAL: could not plant state\n" + visible()[-800:])
        p.kill()
        sys.exit(1)
    kill_conn()
    buf = b""
    send(r"echo ($WSMVAR + '|' + $(try { Get-WsmMarker } catch { 'FUNCGONE' }) "
         r"+ '|' + (Get-Location).Path)" + "\r", 0.3)
    check("variable, function AND cwd all survive the re-dial",
          expect(r"PLANTED\|FUNCALIVE\|C:\\Windows", 60))

elif SCENARIO == "blackhole":
    # The case that used to hang the shell FOREVER. A command's context is
    # cancel-only, so before the fix write() set no socket deadline at all; with
    # the path silently discarding traffic, no RST ever arrives and the response
    # read blocks in netpoll indefinitely. Ctrl-C cannot rescue it either, since
    # StopPipelines wants the same connection mutex the wedged read holds.
    # deadCommsBackstop (120s) is what now bounds it.
    buf = b""
    send("Start-Sleep -Seconds 20; $m='DONE'+'SLEEP'; echo $m\r", 0.3)
    time.sleep(3)
    kill_conn("blackhole")
    t0 = time.time()
    # Generous ceiling: the backstop is 120s, plus retry and re-dial.
    freed = expect(r"connection to the target dropped|Error:", 260)
    waited = time.time() - t0
    check(f"the wedged read is bounded, not infinite (freed after {waited:.0f}s)", freed)
    check("it took at least the backstop, i.e. it really was the deadline firing",
          freed and waited >= 100)

else:
    print(f"unknown scenario {SCENARIO!r}")
    p.kill()
    sys.exit(2)

send("exit\r", 0.5)
time.sleep(1)
p.kill()
trace.close()

if TRACE != "/dev/null":
    data = open(TRACE, "rb").read().decode("utf8", "replace")
    print(f"\n-- transport: {data.count('leg1')} NTLM handshakes, "
          f"{data.count('request failed')} failed requests --", flush=True)
print(f"\n{sum(results)}/{len(results)} checks passed")
sys.exit(0 if all(results) else 1)
