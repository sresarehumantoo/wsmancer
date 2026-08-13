#!/usr/bin/env python3
"""Prove what happens when the target has genuinely FORGOTTEN our shell.

This is a different failure from a severed TCP connection (see
connection-break-test.py) and the difference is the point. A dropped connection
re-attaches to the *same* shell, so the runspace survives -- variables,
functions, working directory, -s scripts. A forgotten shell cannot be
re-attached at all: WinRM restarted, an administrator removed it, or its
IdleTimeout (PT30M) elapsed, and the ShellId is gone for good. Recovery means a
NEW shell, and a new runspace means the operator's state is gone with it.

So there are two things to prove, and the second is the one that matters:

  1. The session RECOVERS -- a new shell is opened and the prompt works again,
     rather than every later command failing identically against a dead ShellId.
  2. The operator is TOLD the state was lost. Silently re-creating would be the
     dangerous outcome, not the convenient one: bypass-4msi patches AMSI in the
     process the shell runs in, so a new shell is unpatched. An operator who
     believed their patch survived would run the next post-ex command straight
     into AMSI. Losing state is survivable; not knowing it was lost is not.

How the shell is forgotten: rather than restarting WinRM (which needs privileges
an ordinary account does not have, and would disrupt every other harness), this
removes precisely one shell. The session under test reports the PID of the
wsmprovhost.exe serving it; a SECOND connection enumerates the listener's shells
and removes the one with that ProcessId. Surgical, unprivileged -- a user may
remove their own shells -- and it leaves the box otherwise untouched.

TRAPS this harness is built against, all of which have bitten scripts here
before:

  * The terminal echoes what we type, so an assertion can match its own input.
    Every marker is assembled ON THE TARGET ('SENT'+'INEL') so the echoed line
    cannot satisfy the match -- only real command output can.
  * An absence check passes for free when nothing ran at all. "The variable is
    gone" is therefore never asserted alone: the same command also emits a
    liveness marker, so the assertion can only pass if the new shell really ran
    it AND the variable really was empty.
  * A bare pty.openpty() has nothing to answer the editor's startup DSR cursor
    query (ESC[6n), and the reader blocks in a way that looks exactly like a
    transport hang. The read loop answers it. See docs/verification.md's DSR trap.

Usage:
  scripts/shell-forgotten-test.py <host> <user> <realm> <password> [trace]

Findings are recorded in docs/verification.md.
"""
import os, pty, select, struct, subprocess, sys, termios, fcntl, time, re

if len(sys.argv) < 5:
    sys.exit(__doc__)
HOST, USER, REALM, PASS = sys.argv[1:5]
TRACE = sys.argv[5] if len(sys.argv) > 5 else "/dev/null"

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.path.join(ROOT, "wsmancer")
ESC_RE = re.compile(rb'\x1b\[[0-9;?]*[a-zA-Z]|\x1b[=>]|\r')
DSR = re.compile(rb'\x1b\[6n')          # the editor's cursor-position query
PROMPT = r"PS [^\n]*> "

master, slave = pty.openpty()
fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 50, 120, 0, 0))
trace = open(TRACE, "wb")
env = dict(os.environ) | {"TERM": "xterm-256color"}
p = subprocess.Popen(
    [BIN, "-i", HOST, "-u", USER, "-r", REALM, "-p", PASS],
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


def pump(seconds):
    """Drain the PTY for a while, answering the editor's DSR query."""
    end = time.time() + seconds
    while time.time() < end:
        r, _, _ = select.select([master], [], [], 0.05)
        if r:
            try:
                c = os.read(master, 65536)
            except OSError:
                return
            if c:
                globals()['buf'] += c
                if DSR.search(c):
                    os.write(master, b'\x1b[24;1R')


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
    pump(settle)


def run(cmd, settle=0.3):
    """Type a command from a cleared buffer, so matches cannot come from an
    earlier step's output still sitting on screen."""
    global buf
    buf = b""
    send(cmd + "\r", settle)


def fatal(msg):
    print(f"FATAL: {msg}\n" + visible()[-1500:], flush=True)
    p.kill()
    sys.exit(1)


# ---------------------------------------------------------------- connect
if not expect(PROMPT):
    fatal("no prompt")
print("== connected ==", flush=True)

# ---------------------------------------------------------------- plant state
# Each value is assembled on the target so the echoed input cannot match it.
run("$marker = 'SENT' + 'INEL7F3A'")
if not expect(PROMPT, 30):
    fatal("no prompt after planting the variable")
run("function Get-Marker { 'FUNC' + 'OK9B2C' }")
if not expect(PROMPT, 30):
    fatal("no prompt after planting the function")
run("cd C:\\Windows\\Temp")
if not expect(PROMPT, 30):
    fatal("no prompt after cd")

# Control: the state really is there before we break anything. Without this a
# later "the state is gone" result would be indistinguishable from never having
# planted it -- the harness would pass for the wrong reason.
#
# STATE_PROBE is deliberately the SAME command here and after recovery, so the
# two results are a real differential rather than two probes that could differ
# for unrelated reasons. It reads the function through Get-Command rather than
# calling it: an undefined function does not evaluate to empty, it throws
# CommandNotFoundException and takes the whole expression's output with it --
# which would leave the post-recovery check matching nothing and passing or
# failing for reasons that have nothing to do with the state.
STATE_PROBE = ("'STATE=[' + $marker + '][' + "
               "(Get-Command Get-Marker -ErrorAction SilentlyContinue).Name + ']'")

run(STATE_PROBE)
check("control: planted state is readable before the shell is lost",
      expect(r"STATE=\[SENTINEL7F3A\]\[Get-Marker\]", 40))
expect(PROMPT, 30)

run("'CWD' + '=' + (Get-Location).Path")
in_temp = expect(r"CWD=C:\\Windows\\Temp", 40)
check("control: working directory was changed before the shell is lost", in_temp)
expect(PROMPT, 30)

# ---------------------------------------------------------------- identify it
run("'PID' + '=' + $PID")
if not expect(r"PID=\d+", 40):
    fatal("could not read the serving process PID")
old_pid = re.search(r"PID=(\d+)", visible()).group(1)
expect(PROMPT, 30)
print(f"== session is served by wsmprovhost PID {old_pid} ==", flush=True)

# ---------------------------------------------------------------- forget it
# A second connection removes exactly this shell. Get-WSManInstance reports each
# shell's ProcessId, which is what ties an enumerated ShellId back to the
# session under test.
ps = (
    "$target = Get-WSManInstance -ResourceURI shell -Enumerate | "
    f"Where-Object {{ $_.ProcessId -eq {old_pid} }}; "
    "if (-not $target) { 'NOTFOUND'; exit }; "
    "Remove-WSManInstance -ResourceURI shell -SelectorSet @{ShellId=$target.ShellId}; "
    "'REMOVED=' + $target.ShellId"
)
killer = subprocess.run(
    [BIN, "-i", HOST, "-u", USER, "-r", REALM, "-p", PASS, "-x", ps],
    capture_output=True, text=True, timeout=180)
killer_out = killer.stdout + killer.stderr
if "REMOVED=" not in killer_out:
    fatal("could not remove the shell from a second connection:\n" + killer_out[-1200:])
print(f"== removed the shell out from under the session ==", flush=True)
pump(2.0)

# ---------------------------------------------------------------- the payload
# The next command hits a shell the server no longer has.
run("'UNREACH' + 'ABLE'", 0.5)
told = expect("no longer has this shell", 90)
check("the operator is told the shell is gone, not shown a raw wsman fault", told)
check("the operator is told a new shell was opened",
      told and re.search("new shell has been opened", visible()) is not None)
check("the operator is told session state was LOST",
      told and re.search("[Ss]ession state was LOST", visible()) is not None)
# The bypass-4msi consequence is the reason this warning exists at all, so the
# warning naming it is itself under test -- an operator who is not told cannot
# know to re-patch.
check("the warning names what has to be re-loaded (-s scripts, bypass-4msi)",
      told and re.search(r"-s scripts", visible()) is not None
      and re.search(r"bypass-4msi", visible()) is not None)
# The raw four-layer wsman fault must not be what the operator reads.
check("the raw wsman fault envelope is not dumped to the terminal",
      "w:InvalidSelectors" not in visible())
expect(PROMPT, 60)

# ---------------------------------------------------------------- still usable
run("'ALI' + 'VE5D1E'", 0.5)
usable = expect("ALIVE5D1E", 60)
check("the shell is usable again after recovery", usable)
expect(PROMPT, 30)

# The new shell must be a genuinely different runspace, not the old one somehow
# re-attached -- otherwise "state was lost" would be a lie in the other
# direction, and the warning would be crying wolf.
run("'PID' + '=' + $PID")
got_new_pid = expect(r"PID=\d+", 40)
new_pid = re.search(r"PID=(\d+)", visible()).group(1) if got_new_pid else None
check("recovery opened a genuinely new shell (different serving process)",
      got_new_pid and new_pid != old_pid)
expect(PROMPT, 30)

# ---------------------------------------------------------------- state is gone
# The same probe the control ran, so this is a true differential. It is also a
# paired assertion: the STATE= prefix only appears if the new shell really
# executed the command, so an empty result cannot be satisfied by a dead shell
# producing nothing at all -- which is exactly how an absence check passes for
# free.
run(STATE_PROBE, 0.5)
gone = expect(r"STATE=\[\]\[\]", 60)
check("session state is genuinely gone in the new shell (and it ran the command)",
      gone)
expect(PROMPT, 30)

# The prompt must not still claim the old working directory: the new runspace
# starts wherever the target puts it, and a stale prompt would have the operator
# believe they are somewhere they are not.
run("'CWD' + '=' + (Get-Location).Path")
back_to_default = expect(r"CWD=", 40) and not re.search(
    r"CWD=C:\\Windows\\Temp", visible())
check("working directory is the new shell's, not the lost one's",
      in_temp and back_to_default)
expect(PROMPT, 30)
check("the prompt no longer displays the lost working directory",
      "PS C:\\Windows\\Temp>" not in visible())

# ---------------------------------------------------------------- done
send("exit\r", 1.0)
try:
    p.wait(timeout=20)
except subprocess.TimeoutExpired:
    p.kill()
trace.close()

passed, total = sum(results), len(results)
print(f"\n{passed}/{total} checks passed", flush=True)
sys.exit(0 if passed == total else 1)
