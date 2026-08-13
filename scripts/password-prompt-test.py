#!/usr/bin/env python3
"""Prove the interactive password prompt, which only a real terminal can show.

With no -p, no -H and no -K the tool asks for a password. Everything that makes
that safe is invisible to a unit test: echo has to be off while it reads, the
prompt has to go to stderr (stdout is a machine-readable stream under -o json),
it must not appear at all when stdin is not a terminal (a piped session would
block forever on a read nobody answers), and Ctrl-C at the prompt has to leave
the operator's terminal usable.

The no-echo check reads the pty's termios rather than looking for the password
on screen: absence of a string proves very little (it could be anywhere in a
redraw), while the ECHO bit being clear at the moment of the read is the
mechanism itself.

Usage: scripts/password-prompt-test.py <host> <user> <realm> <password>
"""
import os, pty, select, struct, subprocess, sys, termios, fcntl, time, re, signal

if len(sys.argv) != 5:
    sys.exit(__doc__)
HOST, USER, REALM, PASS = sys.argv[1:5]
BIN = "./wsmancer"

ESC_RE = re.compile(rb'\x1b\[[0-9;?]*[a-zA-Z]|\x1b[=>]|\r')
DSR = re.compile(rb'\x1b\[6n')          # the editor's cursor-position query, see docs/verification.md

results = []
def check(name, ok, detail=""):
    results.append(ok)
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + ("" if ok else f"\n          {detail!r}"))


class Term:
    def __init__(self, *extra, stdout_to=None):
        self.master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 50, 120, 0, 0))
        cmd = [BIN, "-i", HOST, "-u", USER, "-r", REALM] + list(extra)
        self.out = open(stdout_to, "wb") if stdout_to else slave
        self.p = subprocess.Popen(cmd, stdin=slave, stdout=self.out, stderr=slave,
                                  env=dict(os.environ, TERM="xterm-256color"),
                                  close_fds=True)
        os.close(slave)
        self.buf = b""

    def drain(self, timeout=0.5):
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

    def expect(self, pat, timeout=60):
        end = time.time() + timeout
        while time.time() < end:
            if re.search(pat, self.visible()):
                return True
            self.drain(0.3)
        return False

    def visible(self):
        return ESC_RE.sub(b'', self.buf).decode("utf8", "replace")

    def send(self, data, settle=0.4):
        os.write(self.master, data if isinstance(data, bytes) else data.encode())
        time.sleep(settle)

    def echo_on(self):
        """Is the pty echoing? termios lives on the pty, so the master sees it."""
        return bool(termios.tcgetattr(self.master)[3] & termios.ECHO)

    def wait(self, timeout=30):
        end = time.time() + timeout
        while self.p.poll() is None and time.time() < end:
            self.drain(0.3)
        return self.p.poll()


# ---- 1. the prompt appears, with echo off, and the password is used ----
t = Term()
check("a password is prompted for when none was given",
      t.expect(r"Enter Password: ", 30), t.visible()[-200:])
# The mechanism, not the symptom: ECHO must be clear while the read is pending.
check("terminal echo is off while the password is read", not t.echo_on())

t.send(PASS + "\r", 0.6)
check("the typed password is not echoed", PASS not in t.visible(), t.visible()[-200:])
# Whether the prompted password actually reached the auth path -- a connection is
# the only thing that can prove it, and it fails loudly if the wrong bytes went.
check("the prompted password authenticates", t.expect(r"wsmancer shell", 90),
      t.visible()[-300:])
# Echo is deliberately NOT asserted here: the line editor has taken over by now
# and holds raw mode for the duration of each read, so ECHO is legitimately off.
# The restore is asserted below, on the one-shot path that never starts an
# editor, and on the Ctrl-C path.
t.send("\x04", 0.3)      # Ctrl-D out
t.wait()

# ---- 2. Ctrl-C at the prompt: exit, and leave the terminal usable ----
# Go kills the process on SIGINT by default, which would skip the restore and
# leave the operator's shell with echo off long after the tool has gone.
t = Term()
if not t.expect(r"Enter Password: ", 30):
    print("FATAL: no prompt for the Ctrl-C case")
    sys.exit(1)
t.p.send_signal(signal.SIGINT)
code = t.wait(15)
check("Ctrl-C at the prompt exits", code is not None, f"exit={code}")
check("Ctrl-C at the prompt restores terminal echo", t.echo_on())

# ---- 3. no terminal, no prompt ----
# A piped session must fail with the credentials error rather than block on a
# read nobody is there to answer.
piped = subprocess.run([BIN, "-i", HOST, "-u", USER, "-r", REALM, "-x", "whoami"],
                       stdin=subprocess.DEVNULL, capture_output=True, timeout=60)
err = piped.stderr.decode("utf8", "replace")
check("a non-terminal stdin is not prompted", "Enter Password" not in err, err[-200:])
check("a non-terminal stdin gets the credentials error", "no credentials" in err, err[-200:])

# ---- 4. the prompt never lands on stdout ----
# Under -o json stdout is a machine-readable stream; a prompt written into it
# would corrupt the first object.
jsonout = "/tmp/wsm-prompt-stdout.json"
t = Term("-o", "json", "-x", "whoami", stdout_to=jsonout)
check("the prompt still appears under -o json", t.expect(r"Enter Password: ", 30),
      t.visible()[-200:])
t.send(PASS + "\r", 0.6)
t.wait(90)
# A one-shot run starts no editor, so nothing else can be holding raw mode: if
# ECHO is off here, the prompt failed to restore it.
check("terminal echo is restored once the prompt is done", t.echo_on())
with open(jsonout, "rb") as f:
    body = f.read().decode("utf8", "replace")
check("the prompt is not written to stdout", "Enter Password" not in body, body[:200])
check("stdout carries the JSON result", '"output"' in body, body[:200])
os.unlink(jsonout)

print(f"\n== {sum(results)}/{len(results)} passed ==")
sys.exit(0 if all(results) else 1)
