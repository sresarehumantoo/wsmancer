#!/usr/bin/env python3
"""Drive the shell's line editor through a PTY against a live box.

Line editing, history, Tab completion and Ctrl-key handling take a completely
different code path from piped stdin, so none of it is observable in a normal
test, this opens a pseudo-terminal and sends real keystrokes. (While the liner
fallback existed this file was reef-pty-test.py and there was a second harness
for liner, pinned to it by env var. One editor, one harness.)

Assertions are semantic, which command actually RAN, rather than scraped from
the editor's redraw escapes, which are its business and change with the library.
Two traps follow from that, and both have made a check here hold unconditionally
before:

  * the terminal echoes the line as typed, so a token spelled literally in the
    command matches its own echo. Where the point is that a command ran, the
    token is built ON THE TARGET ('D-' + 'TWO') so only real output can match;
  * the ghost text renders a *previous* command inline, so "the string is on
    screen" can be true with nothing having run at all.

The colored prompt and Ctrl-L are the exceptions: they are about what the editor
draws, so they have to look at the escapes.

Ctrl-C-during-a-command is delivered with a real SIGINT to the child process,
NOT a ^C byte through the PTY: establishing a controlling terminal for the child
so the line discipline delivers the signal is fiddly and orthogonal to what we're
testing (the shell's SIGINT handler + the editor restoring cooked mode on
return). A real terminal delivers the signal the normal way.

Usage: scripts/pty-test.py <host> <user> <realm> <password>

Two things about the target are derived rather than hardcoded, and either can be
overridden when the derivation doesn't hold: WSM_WHOAMI is what the box answers
`whoami` with (default: the realm's first label + the account, lower-case, as
Windows prints it), and WSM_HOMEDIR is a directory the account can write to
(default: C:\\Users\\<user>).
"""
import os, pty, select, struct, subprocess, sys, termios, fcntl, time, re, signal

if len(sys.argv) != 5:
    sys.exit(__doc__)
HOST, USER, REALM, PASS = sys.argv[1:5]
CMD = ["./wsmancer", "-i", HOST, "-u", USER, "-r", REALM, "-p", PASS]

# Matched against the terminal, so it is a regex: escape the backslash and any
# punctuation an account name might carry.
WHOAMI = re.escape(os.environ.get(
    "WSM_WHOAMI", f"{REALM.split('.')[0].lower()}\\{USER.lower()}"))
HOMEDIR = os.environ.get("WSM_HOMEDIR", rf"C:\Users\{USER}")

ESC_RE = re.compile(rb'\x1b\[[0-9;?]*[a-zA-Z]|\x1b[=>]|\r')
DSR = re.compile(rb'\x1b\[6n')          # the editor's cursor-position query
CTRL_A, CTRL_C, CTRL_D = b'\x01', b'\x03', b'\x04'
CTRL_E, CTRL_L, CTRL_U = b'\x05', b'\x0c', b'\x15'
UP, DOWN, RIGHT = b'\x1b[A', b'\x1b[B', b'\x1b[C'
TAB, CR = b'\t', b'\r'


class Term:
    def __init__(self):
        self.master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 50, 120, 0, 0))
        self.p = subprocess.Popen(
            CMD, stdin=slave, stdout=slave, stderr=slave, close_fds=True,
            env=dict(os.environ, TERM="xterm-256color"))
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
                if DSR.search(c):                    # answer so reeflective renders fully
                    os.write(self.master, b'\x1b[24;1R')
                end = time.time() + timeout
        return self.buf

    def send(self, data, settle=0.4):
        os.write(self.master, data if isinstance(data, bytes) else data.encode())
        time.sleep(settle)
        self.drain(0.3)

    def clear(self):
        self.drain(0.2)
        self.buf = b""

    def visible(self):
        return ESC_RE.sub(b'', self.buf).decode("utf8", "replace")

    def raw(self):
        return self.buf.decode("utf8", "replace")

    def expect(self, pat, timeout=30.0):
        end = time.time() + timeout
        while time.time() < end:
            if re.search(pat, self.visible()):
                return True
            self.drain(0.3)
        return False

    # Run a command and wait for its output, so a test never races against a
    # still-running pipeline. The marker is unique per call and the buffer is
    # cleared first: matching a stale marker from an earlier sync would return
    # immediately and let the next test type while the shell is still busy.
    _sync_n = 0

    def sync(self):
        Term._sync_n += 1
        marker = f"WSM-SYNC-{Term._sync_n}"
        self.clear()
        self.send(f"echo {marker}" + "\r", 0.2)
        return self.expect(re.escape(marker) + r"[\s\S]*?PS .*> ")


results = []
def check(name, ok, detail=""):
    results.append(ok)
    print(f"  {'PASS' if ok else 'FAIL':4}  {name}" + ("" if ok else f"\n          {detail!r}"))


t = Term()
if not t.expect(r"wsmancer shell") or not t.expect(r"PS .*> "):
    print("FATAL: shell never started:\n" + t.raw()[-1500:])
    sys.exit(1)
print("== connected (default editor) ==")

# Colored prompt: the prompt line should carry an SGR color escape. Note this
# says nothing about *which* editor is running, color is decided by
# output.Colors, and the plain reader gets it too. The ghost-text checks below
# are the ones that can only pass under the real terminal editor.
check("the editor renders a colored prompt",
      bool(re.search(r'\x1b\[[0-9;]*m.*PS ', t.raw())), t.raw()[-200:])

# Baseline: run whoami to seed history.
t.clear(); t.send("whoami" + "\r", 0.5)
check("baseline whoami runs", t.expect(WHOAMI), t.visible()[-160:])

# GHOST TEXT: type the prefix, accept the suggestion, assert the FULL command ran.
t.clear(); t.send("who")                       # ghost 'ami' should appear
rendered = "whoami" in t.visible()
t.send(RIGHT)                                  # accept the autosuggestion
t.send(CR, 0.6)
check("ghost text renders the suggestion inline", rendered, t.visible()[-160:])
check("accepting ghost text runs the FULL command", t.expect(WHOAMI),
      t.visible()[-160:])

# Ctrl-E accepts the ghost text too, the way zsh-autosuggestions does, it is
# bound to a macro (End then Right) rather than plain end-of-line. Seeded with a
# distinctive marker so the assertion can only pass if the FULL suggested line
# ran, not just the typed prefix.
t.clear(); t.send("Write-Output GHOSTVIACTRLE" + "\r", 0.6)
check("baseline marker command runs", t.expect(r"GHOSTVIACTRLE"), t.visible()[-160:])
t.clear(); t.send("Write-Output GHO")           # ghost should complete the marker
t.send(CTRL_E)                                  # accept via Ctrl-E, not Right
t.send(CR, 0.6)
check("Ctrl-E accepts ghost text (ran the FULL command)",
      t.expect(r"GHOSTVIACTRLE"), t.visible()[-160:])

# Line editing: build 'whoami' from 'hoami' via Ctrl-A / Ctrl-E. This is also the
# regression guard for the binding above: with no suggestion pending, Ctrl-E must
# still be a plain end-of-line.
t.clear(); t.send("hoami"); t.send(CTRL_A); t.send("w"); t.send(CTRL_E); t.send(CR, 0.5)
check("Ctrl-A/E edit the line (ran whoami)", t.expect(WHOAMI),
      t.visible()[-160:])

# Tab completion of a Windows (backslash) remote path, the case reeflective's
# own shell tokeniser would mangle without the explicit PREFIX override.
t.clear(); t.send("download C:\\Us"); t.send(TAB, 1.0)
check("Tab completes a Windows backslash path (C:\\Users)",
      "C:\\Users" in t.visible(), t.visible()[-160:])
t.send(CTRL_U)  # clear the line before the next test

# Tab completion of a remote path CONTAINING A SPACE. This is the case that
# needs requoteAfter: the shell quotes such a path by wrapping the whole value
# ("C:\...\x y\"), which cannot prefix-match the unquoted word the user typed, so
# reeflective would filter it out entirely. The candidate is instead quoted after
# the typed prefix, which both matches and tokenizes back to the true path.
#
# Asserted semantically: complete the path, run `dir` on it, and require the
# marker file inside to be listed. A line that merely *looks* right but parses
# into two arguments would list the wrong directory and fail here.
SPACEDIR = HOMEDIR + r"\wsm space dir"
t.clear()
t.send(f'mkdir "{SPACEDIR}" | Out-Null; ni "{SPACEDIR}\\WSMMARKER.txt" | Out-Null; echo SETUPOK\r', 0.4)
if not t.expect("SETUPOK", 30):
    print("FATAL: could not create the space-bearing test dir:\n" + t.visible()[-400:])
    sys.exit(1)

t.clear(); t.send("dir " + HOMEDIR + r"\wsm"); t.send(TAB, 1.5)
completed = t.visible()
check("Tab offers a remote path containing a space",
      "space dir" in completed, completed[-200:])
t.send(CR, 1.0)
check("the completed space path parses back to one argument (WSMMARKER listed)",
      t.expect("WSMMARKER", 30), t.visible()[-300:])

t.clear()
t.send(f'rm -Recurse -Force "{SPACEDIR}"; echo CLEANOK\r', 0.4)
t.expect("CLEANOK", 30)

# The rest of the completion surface: which side of the wire each argument is
# resolved against, and that a completed directory can be descended into.
t.sync()
t.clear(); t.send("upload /etc/hostnam"); t.send(TAB, 0.6)
check("Tab completes a LOCAL path (upload arg 1)",
      t.expect(re.escape("/etc/hostname"), 8), t.visible()[-160:])
t.send(CTRL_U)

t.clear(); t.send("upload /etc/hostname C:\\Use"); t.send(TAB, 0.8)
check("Tab completes a remote path (upload arg 2)",
      t.expect(re.escape("C:\\Users"), 12), t.visible()[-160:])
t.send(CTRL_U)

t.clear(); t.send('download "C:\\Program Files\\Wind'); t.send(TAB, 0.8)
check("Tab descends into a completed directory",
      t.expect(r"Windows Defender", 12), t.visible()[-200:])
t.send(CTRL_U)

# A path-shaped first word is an executable ON THE TARGET, so it completes
# remotely even though the first word normally offers commands and built-ins.
t.clear(); t.send("C:\\Wind"); t.send(TAB, 0.8)
check("Tab completes a drive-path first word on the target",
      t.expect(re.escape("C:\\Windows"), 12), t.visible()[-160:])
t.send(CTRL_U)

# Arrow-key history. The tokens are concatenated on the target: the recalled line
# is echoed and drawn as ghost text, so a literal token would match without any
# command having run.
t.sync()
t.clear(); t.send("echo ('HIST-' + 'ALPHA')" + "\r", 0.3)
t.expect(r"HIST-ALPHA[\s\S]*?PS .*> ")
t.clear()                       # so only the recalled run can satisfy the check
t.send(UP); t.send(CR, 0.3)
check("Up arrow recalls and re-runs history", t.expect(r"HIST-ALPHA", 20),
      t.visible()[-200:])

# Down walks back toward the newest entry: Up Up lands on D-ONE, Down returns to
# D-TWO, so what runs must be D-TWO.
t.sync()
t.send("echo ('D-' + 'ONE')" + "\r", 0.3); t.expect(r"D-ONE[\s\S]*?PS .*> ")
t.send("echo ('D-' + 'TWO')" + "\r", 0.3); t.expect(r"D-TWO[\s\S]*?PS .*> ")
t.clear()
t.send(UP); t.send(UP); t.send(DOWN); t.send(CR, 0.3)
ran = t.expect(r"D-TWO", 20)
check("Down arrow walks history forward", ran and "D-ONE" not in t.visible(),
      t.visible()[-200:])

# Ctrl-C at an idle prompt abandons the line rather than killing the session.
t.sync()
t.clear()
t.send("echo ('SHOULD-' + 'NOT-RUN')")
t.send(CTRL_C)
t.send(CR, 0.2)                 # empty line -> just a new prompt
t.send("echo ('AFTER-' + 'CTRLC')" + "\r", 0.3)
check("Ctrl-C at idle keeps the session alive",
      t.expect("AFTER-CTRLC", 20) and t.p.poll() is None, t.visible()[-200:])
# The concatenated token can only appear as OUTPUT: every repaint of the
# abandoned line carries it split, exactly as typed.
check("Ctrl-C discarded the line instead of running it",
      "SHOULD-NOT-RUN" not in t.visible(), t.visible()[-300:])

# Ctrl-L clears the screen. This one has to look at the escapes -- clearing IS a
# drawing operation. It must be the *whole screen* erase (CSI 2 J) specifically:
# every ordinary keystroke repaint ends with CSI 0 J (erase to end of display),
# so a check that accepted any erase-in-display would pass on a build where
# Ctrl-L did nothing but redraw the line. Measured on the live editor.
t.sync()
t.clear()
t.send(CTRL_L)
t.drain(0.6)
check("Ctrl-L clears the screen", "\x1b[2J" in t.raw(), repr(t.raw()[:160]))
t.send(CTRL_U)

# Ctrl-C during a running command: real SIGINT -> cancel -> prompt returns.
t.clear(); t.send("sleep 30" + "\r", 0.5); t.drain(1.5)
t.p.send_signal(signal.SIGINT)
check("Ctrl-C during command cancels", t.expect(r"canceling command", 20))
check("shell returns to prompt after cancel", t.expect(r"canceling command\)?\s*\r?\n?PS .*> ", 20))
t.send("echo ALIVE" + "\r", 0.4)
check("session survives the cancel", t.expect("ALIVE") and t.p.poll() is None)

# Ctrl-D exits cleanly. Closing the runspace and the shell costs a few round
# trips, so poll rather than assuming it is instant.
t.sync()
t.send(CTRL_D, 0.2)
deadline = time.time() + 30
while t.p.poll() is None and time.time() < deadline:
    t.drain(0.3)
code = t.p.poll()
check("Ctrl-D exits cleanly", code == 0, f"exit={code}")
if code is None:
    t.p.kill()

print(f"\n{sum(results)}/{len(results)} checks passed")
sys.exit(0 if all(results) else 1)
