#!/usr/bin/env python3
"""Live validation of batch mode (`-x -`), against a real target.

`-x -` reads commands from stdin, one per line, and runs each through the shell's
own dispatch over ONE authenticated connection. It is the multi-command form of
-x, and the whole reason it exists is the property no sequence of separate -x
calls can have: the runspace persists, so a variable, a working directory, or a
function established on one line is still there on the next -- one handshake,
many commands, structured output streaming out as each completes.

What this proves, none of which a unit test can (they have no target, so the
runspace, the wire and the NDJSON-per-command stream are all absent there):

  - state persists across lines over one connection: a $var, a cd, and a defined
    function set on an early line are visible on a later one;
  - the CONTROL that makes that claim non-vacuous: the same three probes issued
    as SEPARATE -x processes do NOT share state -- so a passing persistence row
    is the single connection, not some target-side accident;
  - -o json emits exactly one parseable object per command line (NDJSON), each
    typed "result", and nothing else -- no banner, no prompt -- reaches stdout;
  - the JSON request protocol: a line that is a {"id":..., "command":...} object
    runs the command and echoes the id on its response, so an agent can correlate
    a pipelined stream; a bare line mixed in carries no id;
  - a failure mid-batch does not abort the run: the lines after it still execute
    and still emit their object, the failing line alone carries had_errors, and
    the aggregate exit code is 1;
  - an all-succeeding batch exits 0; blank lines are skipped, not dispatched.

Differential (the repo's rule that a harness must be able to fail): the built-in
CONTROL is the differential. If batch mode secretly reconnected per line (or a
future refactor broke the single-runspace guarantee), the persistence rows would
read the same empty state the separate-process control does, and they would fail
while the control still passes. There is also a coarse differential against any
build predating this feature: it has no `-x -`, so `-` is sent to PowerShell as a
literal command and the batch-capability rows fail -- which is why the per-line
control, not the old binary, is the real discriminator. Measured on Forest
2026-08-01: 16/16 on this build, 4/16 on the pre-feature binary (the 4 that hold
are the control, the single error object still being valid JSON, no prose on
stdout, and the literal `-` command coincidentally exiting 1). Re-measure rather
than copying these forward if a row moves.

The forgotten-shell recovery event (`{"type":"event","event":"shell_recovered"}`)
is NOT exercised here: provoking it means killing the target's WinRM shell
mid-batch, which scripts/shell-forgotten-test.py already does for the shared
recovery path. Its json rendering is unit-tested in internal/output.

Usage: batch-test.py <host> <user> <realm> <password>
       WSM_BIN overrides the binary (default ./wsmancer, run from repo root)
"""
import json
import os
import subprocess
import sys

if len(sys.argv) != 5:
    sys.exit(__doc__)
HOST, USER, REALM, PW = sys.argv[1:5]
BIN = os.environ.get("WSM_BIN", "./wsmancer")

results = []
def check(name, ok, detail=""):
    results.append(bool(ok))
    print(f"  {'PASS' if ok else 'FAIL'}  {name}")
    if not ok and detail:
        print(f"        {str(detail).strip()[:400]}")

def creds():
    return ["-u", USER, "-r", REALM, "-p", PW]

def batch(commands, *extra, timeout=180):
    """Pipe commands (a list of lines) to one `-x -` invocation over one conn."""
    cmd = [BIN, "-i", HOST] + creds() + list(extra) + ["-x", "-"]
    stdin = "\n".join(commands) + "\n"
    p = subprocess.run(cmd, input=stdin, capture_output=True, text=True, timeout=timeout)
    return p.returncode, p.stdout, p.stderr

def oneshot(command, *extra, timeout=180):
    """One classic -x <command> -- a fresh connection, for the control."""
    cmd = [BIN, "-i", HOST] + creds() + list(extra) + ["-x", command]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return p.returncode, p.stdout, p.stderr

def objs(stdout):
    """Parse an NDJSON stdout into a list of objects, raising on any non-JSON
    line -- so 'a banner leaked onto stdout' surfaces as a parse failure here."""
    out = []
    for ln in stdout.splitlines():
        if ln.strip():
            out.append(json.loads(ln))
    return out

print(f"batch mode (-x -): {BIN} -> {HOST}")

# --- state persists across lines over one connection ---------------------
print("\nstate persistence (one connection, many commands)")
rc, out, err = batch([
    "$wsm = 1337",
    "cd C:\\Windows",
    "function Get-WsmFoo { 'foobar-8f2a' }",
    "Write-Output \"var=$wsm loc=$((Get-Location).Path) fn=$(Get-WsmFoo)\"",
])
persisted = ("var=1337" in out and "loc=C:\\Windows" in out and "fn=foobar-8f2a" in out)
check("a $var, a cd and a function set on early lines survive to a later line",
      rc == 0 and persisted, out + err)

# The control: the SAME probes as three separate -x processes must NOT share
# state. This is what proves the row above is the single connection, not the
# target remembering a variable on its own.
print("\ncontrol: separate -x processes do NOT share state")
_, _, _ = oneshot("$wsm = 1337")               # a fresh process; the var dies with it
rc2, out2, err2 = oneshot("Write-Output \"var=[$wsm]\"")
check("a var set in one -x process is empty in the next (state is not global)",
      "var=[]" in out2, f"got {out2!r} {err2}")

# --- NDJSON: exactly one typed object per command ------------------------
print("\n-o json: one object per command line")
rc, out, err = batch(["whoami", "hostname", "$PSVersionTable.PSVersion.Major"], "-o", "json")
try:
    os_ = objs(out)
except Exception as e:
    check("every stdout line is JSON (no banner/prompt leaked)", False, f"{e}: {out[:300]}")
    os_ = []
else:
    check("every stdout line is JSON (no banner/prompt leaked)", True)
check("three commands yield exactly three objects", len(os_) == 3, f"{len(os_)}: {out[:300]}")
check("each object is typed 'result'",
      all(o.get("type") == "result" for o in os_) and len(os_) == 3,
      json.dumps(os_)[:300])
check("each object echoes its own command",
      [o.get("command") for o in os_] == ["whoami", "hostname", "$PSVersionTable.PSVersion.Major"],
      json.dumps([o.get("command") for o in os_]))
check("no diagnostic prose reached stdout", "wsmancer shell" not in out and "PS " not in out, out[:200])

# --- the JSON request protocol: id correlation ---------------------------
print("\nJSON request protocol (id correlation)")
rc, out, err = batch([
    '{"id": "req-1", "command": "whoami"}',
    '{"id": 2, "command": "hostname"}',
    "hostname",  # a bare line mixed in must carry no id
], "-o", "json")
try:
    os_ = objs(out)
except Exception as e:
    check("request-protocol stream parses", False, f"{e}: {out[:300]}")
    os_ = []
check("a structured request echoes its string id",
      len(os_) >= 1 and os_[0].get("id") == "req-1", json.dumps(os_)[:300])
check("a structured request echoes its numeric id",
      len(os_) >= 2 and os_[1].get("id") == 2, json.dumps(os_)[:300])
check("the command still ran (id did not swallow it)",
      len(os_) >= 1 and any("\\" in str(o) for o in os_[0].get("output", [])),
      json.dumps(os_)[:300])
check("a bare line mixed into a request stream carries no id",
      len(os_) == 3 and "id" not in os_[2], json.dumps(os_)[:300])

# --- a failure mid-batch does not abort the rest -------------------------
print("\nfailure mid-batch is isolated")
rc, out, err = batch([
    "Write-Output aaa-marker",
    "Get-Item C:\\definitely-not-here-9f3a",
    "Write-Output bbb-marker",
], "-o", "json")
try:
    os_ = objs(out)
except Exception as e:
    check("mid-batch failure still yields parseable objects", False, f"{e}: {out[:300]}")
    os_ = []
check("all three lines ran despite the middle one failing", len(os_) == 3, f"{len(os_)}: {out[:300]}")
check("only the failing line carries had_errors",
      len(os_) == 3 and os_[0].get("had_errors") is False and os_[1].get("had_errors") is True
      and os_[2].get("had_errors") is False, json.dumps(os_)[:400])
check("the lines after the failure still produced output",
      "aaa-marker" in json.dumps(os_) and "bbb-marker" in json.dumps(os_), json.dumps(os_)[:400])
check("a batch containing a failure exits 1", rc == 1, f"rc={rc}")

# --- exit codes and blank lines ------------------------------------------
print("\nexit codes and blank lines")
rc, out, err = batch(["Write-Output ok1", "", "  ", "Write-Output ok2"])
check("an all-succeeding batch (with blank lines) exits 0",
      rc == 0 and "ok1" in out and "ok2" in out, f"rc={rc} {out}{err}")

n, total = sum(results), len(results)
print(f"\n{n}/{total} passed")
sys.exit(0 if n == total else 1)
