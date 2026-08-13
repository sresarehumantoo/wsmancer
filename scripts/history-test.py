#!/usr/bin/env python3
"""Prove opt-in persistent history: it survives a reconnect, and it respects the
leading-space opt-out.

Only a real session can prove this. Under the default editor the *library*, not
the shell, decides when a line is accepted and writes it to whichever history
source is registered -- so "does reeflective actually read and write our store"
is a question about reeflective's behavior, not about our code, and a unit test
answering it would only be testing a mock.

The leading-space rule is the sharpest case: the shell trims a line before
dispatching it, so if the raw line were not what reached the store the opt-out
would silently do nothing and the operator would never know their credential
command was on disk.

Answers the editor's cursor-position query, as every PTY harness here must --
see docs/verification.md's DSR trap.

Usage: scripts/history-test.py <host> <user> <realm> <password>
"""
import os, pty, select, struct, subprocess, sys, termios, fcntl, time, re, tempfile

if len(sys.argv) != 5:
    sys.exit(__doc__)
HOST, USER, REALM, PASS = sys.argv[1:5]

ESC_RE = re.compile(rb'\x1b\[[0-9;?]*[a-zA-Z]|\x1b[=>]|\r')
DSR = re.compile(rb'\x1b\[6n')
UP, CR, CTRL_D = b'\x1b[A', b'\r', b'\x04'

HISTDIR = tempfile.mkdtemp(prefix="wsm-hist-")
TAG = "probe-target"
HISTFILE = os.path.join(HISTDIR, TAG + ".hist")

results = []
def check(name, ok, detail=""):
    results.append((name, ok))
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + ("" if ok else f"\n          detail={detail}"))


class Term:
    def __init__(self, *extra):
        self.master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 50, 200, 0, 0))
        cmd = ["./wsmancer", "-i", HOST, "-u", USER, "-r", REALM, "-p", PASS] + list(extra)
        env = dict(os.environ, TERM="xterm-256color", WSMANCER_HISTORY_DIR=HISTDIR)
        self.p = subprocess.Popen(cmd, stdin=slave, stdout=slave, stderr=slave,
                                  env=env, close_fds=True)
        os.close(slave)
        self.buf = b""

    def drain(self, timeout=0.6):
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

    def visible(self):
        return ESC_RE.sub(b'', self.buf).decode("utf8", "replace")

    def send(self, d, settle=0.5):
        os.write(self.master, d if isinstance(d, bytes) else d.encode())
        time.sleep(settle)
        self.drain(0.4)

    def expect(self, pat, timeout=45):
        end = time.time() + timeout
        while time.time() < end:
            if re.search(pat, self.visible()):
                return True
            self.drain(0.3)
        return False

    def quit(self):
        self.send(CTRL_D, 0.3)
        end = time.time() + 30
        while self.p.poll() is None and time.time() < end:
            self.drain(0.3)
        if self.p.poll() is None:
            self.p.kill()


def histfile():
    try:
        with open(HISTFILE) as f:
            return f.read()
    except FileNotFoundError:
        return None


# ---- session 1: run some commands, one of them space-prefixed ----
t = Term("-Y", "--history-tag", TAG)
if not t.expect(r"PS .*> ", 90):
    print("FATAL: no prompt:\n" + t.visible()[-2000:])
    sys.exit(1)
check("the banner says history is on disk",
      "command history:" in t.visible() and "prefix a command with a space" in t.visible(),
      repr(t.visible()[:600]))

t.send("echo HIST-ONE" + "\r", 0.3); t.expect(r"HIST-ONE")
t.send("echo HIST-TWO" + "\r", 0.3); t.expect(r"HIST-TWO")
# The opt-out. Note the leading space. The token is concatenated ON THE TARGET
# so that matching it proves the command produced OUTPUT -- the terminal echoes
# the line as typed, and a token spelled literally would match its own echo and
# prove nothing about whether the command ran.
t.send(" echo ('SECRET-' + 'RAN')" + "\r", 0.3)
ran_secret = t.expect(r"SECRET-RAN", 30)
t.quit()

body = histfile()
check("a history file was written", body is not None, HISTFILE)
check("ordinary commands are recorded",
      body is not None and "echo HIST-ONE" in body and "echo HIST-TWO" in body, repr(body))
# "SECRET-" is how the line was typed; its absence means the whole line was
# skipped, not merely that the concatenated token never appeared.
check("a space-prefixed command is NOT recorded",
      body is not None and "SECRET-" not in body, repr(body))
check("the space-prefixed command still RAN (skipping history must not skip the command)",
      ran_secret, repr(t.visible()[-200:]))
check("the history file is 0600",
      body is not None and (os.stat(HISTFILE).st_mode & 0o777) == 0o600,
      oct(os.stat(HISTFILE).st_mode & 0o777) if body is not None else "no file")

# ---- session 2: reconnect, Up-arrow must reach the previous session ----
t = Term("-Y", "--history-tag", TAG)
if not t.expect(r"PS .*> ", 90):
    print("FATAL: no prompt on reconnect")
    sys.exit(1)
t.drain(0.5)
t.buf = b""
t.send(UP, 0.8)                      # newest entry from the PREVIOUS session
recalled = "echo HIST-TWO" in t.visible()
check("Up-arrow recalls a command from the previous session", recalled,
      repr(t.visible()[-200:]))
t.send(CR, 0.3)
check("the recalled command runs", t.expect(r"HIST-TWO", 30), repr(t.visible()[-200:]))
t.quit()

# ---- session 3: without -Y, nothing is written ----
CLEANDIR = tempfile.mkdtemp(prefix="wsm-hist-off-")
os.environ["WSMANCER_HISTORY_DIR"] = CLEANDIR
t = Term()                            # no -Y
if not t.expect(r"PS .*> ", 90):
    print("FATAL: no prompt (no -Y)")
    sys.exit(1)
check("no history banner when the flag is off", "command history:" not in t.visible(),
      repr(t.visible()[:400]))
t.send("echo NOT-PERSISTED" + "\r", 0.3); t.expect(r"NOT-PERSISTED")
t.quit()
check("nothing is written to disk without -Y", os.listdir(CLEANDIR) == [],
      repr(os.listdir(CLEANDIR)))

print()
failed = [r for r in results if not r[1]]
print(f"== {len(results) - len(failed)}/{len(results)} passed ==")
print(f"   history dir: {HISTDIR}")
sys.exit(1 if failed else 0)
