#!/usr/bin/env python3
"""Prove Ctrl-C aborts the payload-streaming phase (-s script load).

The streaming phase is the gap `sendB64Var` used to have: a Ctrl-C pressed while
a payload was being chunked into a remote variable did nothing, the upload ran to
completion, and the buffered signal was then drained by the *next* command --
which got terminated instead. That is invisible to a unit test, because what
makes it a bug is the interaction between a real SIGINT, the chunk loop and the
next executeAs.

So: load a script big enough to take many chunks, interrupt it mid-stream, and
assert both halves -- the load aborted AND the next command was left alone.

Nothing under test here is editor-specific, but the reader still has to answer
the editor's cursor query or it blocks forever (see docs/verification.md's DSR trap).

Usage: scripts/upload-cancel-test.py <host> <user> <realm> <password>
"""
import os, pty, select, struct, subprocess, sys, termios, fcntl, time, re, tempfile

if len(sys.argv) != 5:
    sys.exit(__doc__)
HOST, USER, REALM, PASS = sys.argv[1:5]

ESC_RE = re.compile(rb'\x1b\[[0-9;?]*[a-zA-Z]|\x1b[=>]|\r')
DSR = re.compile(rb'\x1b\[6n')          # the editor's cursor-position query
CTRL_U, CR = b'\x15', b'\r'

# Big enough that the stream is still running when the SIGINT lands: ~4 MB is
# ~5.5 MB of base64, i.e. ~92 chunks of 60 KiB, each a round trip. Small is still
# multi-chunk, so the happy path exercises the same loop and its length check.
BIG_BYTES, SMALL_BYTES = 4_000_000, 400_000
SCRIPTS = tempfile.mkdtemp(prefix="wsm-cancel-")


def write_script(name, func, size):
    """A real function plus comment padding, so it stays valid PowerShell."""
    head = f"function {func} {{ '{func}-RAN' }}\n"
    pad = "# " + "A" * 78 + "\n"
    body = head + pad * ((size - len(head)) // len(pad))
    with open(os.path.join(SCRIPTS, name), "w") as f:
        f.write(body)
    return len(body)


big_len = write_script("Big.ps1", "Get-WsmCancelProbe", BIG_BYTES)
small_len = write_script("Small.ps1", "Get-WsmLoadProbe", SMALL_BYTES)
CMD = ["./wsmancer", "-i", HOST, "-u", USER, "-r", REALM, "-p", PASS, "-s", SCRIPTS]


class Term:
    def __init__(self):
        self.master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 50, 240, 0, 0))
        self.p = subprocess.Popen(CMD, stdin=slave, stdout=slave, stderr=slave,
                                  env=dict(os.environ, TERM="xterm-256color"),
                                  close_fds=True)
        os.close(slave)
        self.buf = b""

    def drain(self, timeout=0.4):
        end = time.time() + timeout
        while time.time() < end:
            r, _, _ = select.select([self.master], [], [], 0.05)
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

    def expect(self, pat, timeout=60.0):
        end = time.time() + timeout
        while time.time() < end:
            if re.search(pat, self.visible()):
                return True
            self.drain(0.3)
        return False

    def send(self, data, settle=0.35):
        os.write(self.master, data if isinstance(data, bytes) else data.encode())
        time.sleep(settle)

    def clear(self):
        self.drain(0.2)
        self.buf = b""

    def visible(self):
        return ESC_RE.sub(b'', self.buf).decode("utf8", "replace")

    def raw(self):
        return self.buf.decode("utf8", "replace")

    # settle waits for output to stop flowing, used only to let a prompt finish
    # repainting. It is NOT a test for "the shell is idle": chunk commands print
    # nothing, so a shell mid-upload is indistinguishable from an idle one here.
    def settle(self, quiet=3.0, limit=300.0):
        end = time.time() + limit
        while time.time() < end:
            before = len(self.buf)
            self.drain(quiet)
            if len(self.buf) == before:
                return True
        return False

    _sync_n = 0

    def sync(self):
        Term._sync_n += 1
        marker = f"WSM-SYNC-{Term._sync_n}"
        self.clear()
        self.send(f"echo {marker}" + "\r", 0.2)
        return self.expect(re.escape(marker) + r"[\s\S]*?PS .*> ")


results = []
def check(name, ok, detail=""):
    results.append((name, ok))
    line = f"  {'PASS' if ok else 'FAIL'}  {name}"
    if not ok:
        line += f"\n          alive={t.p.poll()} detail={detail}"
    print(line)


# ask runs a probe on the target and returns its visible output.
#
# The token halves are concatenated *on the target* ('PROBE-' + 'DEFINED'), never
# written whole in the command. The terminal echoes the line as typed, so a token
# spelled literally here would match its own echo and the assertion would hold no
# matter what the target said -- which is exactly how an earlier version of this
# harness passed against a build that was still broken.
def ask(expr, token, timeout=30):
    t.clear()
    t.send(expr + "\r", 0.2)
    # Wait for the answer itself, not for a prompt: the editor repaints while
    # echoing, which puts a prompt in the buffer before the command has even run.
    # The token cannot match the echo, which carries it split as 'X-'+'Y'.
    t.expect(token, timeout)
    return t.visible()


def defined(func):
    return ("if (Get-Command %s -EA SilentlyContinue) "
            "{ 'PROBE-'+'DEFINED' } else { 'PROBE-'+'ABSENT' }" % func)


t = Term()
if not t.expect(r"wsmancer shell") or not t.expect(r"PS .*> "):
    print("FATAL: shell never started:\n" + t.raw()[-2000:])
    sys.exit(1)
t.sync()
print(f"== connected (scripts in {SCRIPTS}: Big={big_len}B Small={small_len}B) ==")

# ---- 1. happy path: a multi-chunk script loads, and the length check passes ----
t.clear()
t.send("Small.ps1" + "\r", 0.2)
loaded = t.expect(r"loaded Small\.ps1", 120)
check("a multi-chunk script loads to completion", loaded, repr(t.visible()[-300:]))
check("no truncation reported on a good stream",
      "truncated in transit" not in t.visible(), repr(t.visible()[-300:]))
out = ask(defined("Get-WsmLoadProbe"), r"PROBE-(DEFINED|ABSENT)")
check("the loaded function is defined in the runspace", "PROBE-DEFINED" in out, repr(out[-200:]))

# ---- 2. Ctrl-C mid-stream aborts the upload ----
# The SIGINT is sent directly: the tty signal plumbing needs a controlling
# terminal this harness does not set up, and what is under test is the shell's
# handling, not the kernel line discipline.
t.sync()
t.clear()
t.send("Big.ps1" + "\r", 0.2)
time.sleep(4.0)                      # let several chunks go out
mid_stream = "loaded Big.ps1" not in t.visible()
os.kill(t.p.pid, 2)
check("the SIGINT landed while the stream was still running", mid_stream,
      repr(t.visible()[-300:]))

# Wait for the stream to resolve one way or the other. Waiting on quiescence
# instead would be wrong: chunk commands print nothing, so a shell mid-upload
# looks exactly like an idle one, and every assertion below would race it. A
# fixed build prints the cancellation; a build that ignores the signal runs to
# completion and prints the load. Either settles the question.
t.expect(r"canceled; nothing was run on the target|loaded Big\.ps1", 300)
vis = t.visible()
check("Ctrl-C aborts the payload stream",
      "canceled; nothing was run on the target" in vis, repr(vis[-400:]))
check("the aborted load did not report success", "loaded Big.ps1" not in vis, repr(vis[-300:]))
# reportErr suppresses the cancellation (it unwraps to context.Canceled), so the
# "^C" line above must be the only thing the operator sees.
check("the cancellation is not also printed as an error", "Error:" not in vis, repr(vis[-300:]))
t.settle()   # let the prompt come back before typing again

# ---- 3. THE REGRESSION: the stale signal must not kill the next command ----
# Before the fix the signal stayed buffered (cap 1, nothing drained it) and the
# next executeAs consumed it, printing "^C (canceling command)" and terminating
# a command the operator never meant to stop. This has to be the FIRST command
# after the abort: any other command would drain the stale signal itself and hide
# the bug from the assertion.
t.clear()
t.send("echo NEXT-COMMAND-SURVIVED" + "\r", 0.2)
ran = t.expect(r"NEXT-COMMAND-SURVIVED", 30)
check("the next command runs after an aborted upload", ran, repr(t.visible()[-300:]))
check("the next command was NOT canceled by the stale signal",
      "canceling command" not in t.visible(), repr(t.visible()[-300:]))
check("the session is still alive", t.p.poll() is None, f"exit={t.p.poll()}")

# ---- 4. nothing was run, and the scratch variable was cleaned up ----
out = ask(defined("Get-WsmCancelProbe"), r"PROBE-(DEFINED|ABSENT)")
check("the aborted script was never defined in the runspace",
      "PROBE-ABSENT" in out and "PROBE-DEFINED" not in out, repr(out[-200:]))
out = ask("if (Test-Path Variable:global:__wsm) { 'VAR-'+'PRESENT' } else { 'VAR-'+'CLEAN' }",
          r"VAR-(PRESENT|CLEAN)")
check("the partial payload variable was removed",
      "VAR-CLEAN" in out and "VAR-PRESENT" not in out, repr(out[-200:]))

# ---- 5. the runspace still works: a load after the abort succeeds ----
t.sync()
t.clear()
t.send("Small.ps1" + "\r", 0.2)
check("a script still loads after an aborted one", t.expect(r"loaded Small\.ps1", 120),
      repr(t.visible()[-300:]))

t.send(b'\x04', 0.2)   # Ctrl-D
deadline = time.time() + 30
while t.p.poll() is None and time.time() < deadline:
    t.drain(0.3)
if t.p.poll() is None:
    t.p.kill()

print()
failed = [r for r in results if not r[1]]
print(f"== {len(results) - len(failed)}/{len(results)} passed ==")
sys.exit(1 if failed else 0)
