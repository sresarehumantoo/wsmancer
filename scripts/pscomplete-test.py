#!/usr/bin/env python3
"""Prove parameter/value completion via the target's own TabExpansion2.

The real risk here is not "are there candidates" but "is the line still correct
afterwards". PowerShell reports its own replacement span, which frequently
disagrees with the shell's tokenizer at these sites, and splicing at the wrong
offset produces a line that still *looks* plausible. So the assertions run the
completed command and check its output: a mis-spliced line cannot produce the
right answer.

Every proof token is produced by the target (a "True" it computes), never typed,
so it can be matched neither from the terminal's echo of the input nor from the
editor's inline history suggestion.

Uses the shipped default editor, so it answers the cursor-position query -- see
docs/verification.md's DSR trap.

Usage: scripts/pscomplete-test.py <host> <user> <realm> <password>
"""
import os, pty, select, struct, subprocess, sys, termios, fcntl, time, re

if len(sys.argv) != 5:
    sys.exit(__doc__)
HOST, USER, REALM, PASS = sys.argv[1:5]

ESC_RE = re.compile(rb'\x1b\[[0-9;?]*[a-zA-Z]|\x1b[=>]|\r')
DSR = re.compile(rb'\x1b\[6n')
TAB, CR, CTRL_U, CTRL_D = b'\t', b'\r', b'\x15', b'\x04'

results = []
def check(name, ok, detail=""):
    results.append((name, ok))
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + ("" if ok else f"\n          detail={detail}"))


class Term:
    def __init__(self, *extra):
        self.master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 50, 220, 0, 0))
        cmd = ["./wsmancer", "-i", HOST, "-u", USER, "-r", REALM, "-p", PASS] + list(extra)
        self.p = subprocess.Popen(
            cmd, stdin=slave, stdout=slave, stderr=slave, close_fds=True,
            env=dict(os.environ, TERM="xterm-256color"))
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

    # curline is the text after the last prompt -- i.e. what is on the input line
    # right now. Splitting the buffer on the typed prefix instead would be wrong:
    # the prefix occurs inside its own completion ("Get-Service -Na" is a
    # substring of "Get-Service -Name"), so the tail would read "me" whether or
    # not anything was inserted, and the assertion would hold either way.
    def curline(self):
        return self.visible().split("> ")[-1].strip()

    def clear(self):
        self.drain(0.2)
        self.buf = b""

    def quit(self):
        self.send(CTRL_D, 0.3)
        end = time.time() + 30
        while self.p.poll() is None and time.time() < end:
            self.drain(0.3)
        if self.p.poll() is None:
            self.p.kill()


t = Term()
if not t.expect(r"PS .*> ", 90):
    print("FATAL: no prompt:\n" + t.visible()[-2000:])
    sys.exit(1)
print("== connected ==")

# The authoritative assertion in 1 and 2 is the command's OUTPUT, never the
# rendered line. The editor draws history autosuggestion ("ghost text") inline,
# so a previous test's command can put its text on screen without anything
# having been completed -- an earlier version of this harness "passed" exactly
# that way. A True printed by the target cannot be faked by a redraw.

# ---- 1. parameter NAME completion ----
# Two checks, because the run alone is a weak detector here: PowerShell accepts
# `-Na` as an unambiguous abbreviation of `-Name`, so the command succeeds even
# if nothing was ever completed. The rendered line is what proves the insertion,
# and it is trustworthy at this one point only because this is the FIRST command
# of the session -- there is no history yet, so ghost text cannot supply it.
t.clear()
t.send("Get-Service -Na")
t.send(TAB, 2.0)
check("a parameter name is inserted (-Na -> -Name)",
      t.curline() == "Get-Service -Name", repr(t.curline()))
t.send(" Spooler | %{$_.Name -eq 'Spooler'}")
t.send(CR, 0.3)
check("a completed parameter NAME (-Na -> -Name) yields a line that runs",
      t.expect(r"True", 40), repr(t.visible()[-260:]))

# ---- 2. parameter VALUE completion, proven the same way ----
# Get-Process -Name, not Get-Service -Name: only some cmdlets ship an argument
# completer, and Get-Service's has none on Server 2016 (TabExpansion2 returns 0
# matches). Asserting against a cmdlet with no completer would test nothing.
t.clear()
t.send("Get-Process -Name con")
t.send(TAB, 2.0)
t.send(" | %{$_.ProcessName -eq 'conhost'}")
t.send(CR, 0.3)
check("a completed parameter VALUE (con -> conhost) yields a line that runs",
      t.expect(r"True", 40), repr(t.visible()[-260:]))

# ---- 3. a bare dash completes to some parameter of that cmdlet ----
t.clear()
t.send("Get-Process -")
t.send(TAB, 2.5)
tail = t.visible().split("Get-Process -")[-1]
check("a bare dash completes to a parameter name",
      re.match(r"[A-Za-z]{2,}", tail) is not None, repr(t.visible()[-260:]))
t.send(CTRL_U)

# ---- 3b. an enum value completes. Deliberately NOT executed: running
# Set-ExecutionPolicy would change the target's configuration, and a completion
# test has no business doing that. This command has not been typed earlier in
# the session, so ghost text cannot supply the token.
t.clear()
t.send("Set-ExecutionPolicy -ExecutionPolicy Rem")
t.send(TAB, 2.0)
check("an enum argument completes (Rem -> RemoteSigned)",
      "RemoteSigned" in t.visible(), repr(t.visible()[-200:]))
t.send(CTRL_U)

# ---- 4. paths are NOT rerouted: the proven remote-path completion still runs ----
t.clear()
t.send("Get-ChildItem C:\\Wind")
t.send(TAB, 2.0)
check("a path argument still completes as a path", "C:\\Windows" in t.visible(),
      repr(t.visible()[-160:]))
t.send(CTRL_U)

# ---- 5. the built-ins keep their own argument semantics ----
t.clear()
t.send("upload /etc/hostnam")
t.send(TAB, 1.5)
check("upload's first argument still completes LOCALLY", "/etc/hostname" in t.visible(),
      repr(t.visible()[-160:]))
t.send(CTRL_U)

t.clear()
t.send("donut-loader -pro")
t.send(TAB, 1.5)
check("donut-loader's flags still come from its own list",
      "-process_id" in t.visible(), repr(t.visible()[-160:]))
t.send(CTRL_U)

check("the session is still alive", t.p.poll() is None, f"exit={t.p.poll()}")
t.quit()

# ---- 6. -N disables this site too ----
t = Term("-N")
if not t.expect(r"PS .*> ", 90):
    print("FATAL: no prompt with -N")
    sys.exit(1)
t.clear()
t.send("Get-Service -Na")
t.send(TAB, 2.0)
check("-N suppresses parameter completion",
      t.curline() == "Get-Service -Na", repr(t.curline()))
t.quit()

print()
failed = [r for r in results if not r[1]]
print(f"== {len(results) - len(failed)}/{len(results)} passed ==")
sys.exit(1 if failed else 0)
