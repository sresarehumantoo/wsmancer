#!/usr/bin/env python3
"""Live validation that -x runs the shell's own dispatch, against a real target.

-x used to write its line straight to the runspace, so no built-in had a
non-interactive form: `-x services` ran a cmdlet that does not exist, and
upload, download, menu, help and the loaders could only be reached by typing at
a prompt. That made the port's headline pairing -- `-x` with `-o json`, for a
script or an agent -- able to run PowerShell and nothing this tool adds.

What this proves, none of which a unit test can (they have no target, so every
one of these paths is stubbed or absent there):

  - a built-in actually *runs* over the wire from -x (`services` returns the
    target's service table; the pre-change binary returns a cmdlet-not-found
    error record instead, which is the differential below);
  - upload and download work as one-shots, verified against the target's own
    Get-FileHash rather than the client's self-report;
  - plain PowerShell is unchanged -- the built-ins shadow their remote namesakes
    exactly as they do interactively, and nothing else moved;
  - the exit code is honest in both directions: 0 for success, 1 for a failing
    remote command, which is a script's only signal and is *not* carried by any
    returned error (executeAs renders a PowerShell error record and returns nil,
    so only the shell's `failed` flag distinguishes it);
  - -o json emits one parseable object per run, on the error path too;
  - -l writes a transcript for a one-shot.

Differential (per the repo's rule that a harness must be able to fail): run it
with WSM_BIN pointing at a build from before the change --

    git stash && go build -o /tmp/wsm-old ./cmd/wsmancer && git stash pop
    WSM_BIN=/tmp/wsm-old scripts/oneshot-test.py <host> <user> <realm> <pw>

-- and exactly the six built-in rows fail (help, services, upload, the uploaded
file's hash, download, menu) while every plain-PowerShell, exit-code, json and
transcript row still passes, which is what makes those six the discriminator
rather than a general "the old binary is worse". Measured on Forest 2026-08-01:
16/16 on this build, 10/16 on that one. Re-measure rather than copying these
forward if a row moves.

A trap this harness exists to catch, and did: main.go's ctx comes from
signal.NotifyContext, whose stop() *cancels* it. Passing that ctx to the
one-shot after calling stop() aborts the command before it runs, and the
symptom -- empty output, exit 1 -- is indistinguishable from a target that
rejected the command. Every unit test passed with a fresh context.Background().

Usage: oneshot-test.py <host> <user> <realm> <password>
       WSM_BIN overrides the binary (default ./wsmancer, run from repo root)
       WSM_ADMIN_HASH runs the `services` row as Administrator (an
       unprivileged account cannot open the SCM), e.g. WSM_ADMIN_HASH=<nt-hash>
"""
import hashlib
import json
import os
import subprocess
import sys
import tempfile

if len(sys.argv) != 5:
    sys.exit(__doc__)
HOST, USER, REALM, PW = sys.argv[1:5]
BIN = os.environ.get("WSM_BIN", "./wsmancer")
ADMIN_HASH = os.environ.get("WSM_ADMIN_HASH", "")

results = []
def check(name, ok, detail=""):
    results.append(bool(ok))
    print(f"  {'PASS' if ok else 'FAIL'}  {name}")
    if not ok and detail:
        print(f"        {detail.strip()[:400]}")

def run(command, *extra, admin=False, timeout=180):
    """One -x invocation. Returns (exit code, stdout, stderr)."""
    cmd = [BIN, "-i", HOST]
    if admin and ADMIN_HASH:
        cmd += ["-u", "Administrator", "-H", ADMIN_HASH]
    else:
        cmd += ["-u", USER, "-r", REALM, "-p", PW]
    cmd += list(extra) + ["-x", command]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return p.returncode, p.stdout, p.stderr

tmp = tempfile.mkdtemp(prefix="wsm-1shot-")
payload = bytes((i * 31 + 7) & 0xFF for i in range(9000))
src = os.path.join(tmp, "up.bin")
with open(src, "wb") as f:
    f.write(payload)
want = hashlib.sha256(payload).hexdigest().upper()
remote = "wsm-oneshot.bin"   # relative to the shell's location, so no baked path

print(f"one-shot dispatch: {BIN} -> {HOST}")

# --- plain PowerShell is unchanged ---------------------------------------
print("\nplain PowerShell")
rc, out, err = run("whoami")
check("whoami runs and exits 0", rc == 0 and "\\" in out, out + err)
rc, out, err = run("$a = 6*7; $a")
check("an expression returns its value", rc == 0 and "42" in out, out + err)

# The built-ins shadow their remote namesakes here exactly as they do
# interactively, and the target's own stay reachable under their real cmdlet
# names -- `help` is this tool's, `Get-Help` is the box's. (Clear-Host is the
# other half of that pair but cannot be asserted on: it sets CursorPosition,
# which no non-interactive PSRP host supports, change or no change.)
rc, out, err = run("Get-Help Get-Date | Select-Object -ExpandProperty Synopsis")
check("Get-Help still reaches the target's own help",
      rc == 0 and "Get-Date [" in out and "Any PowerShell command" not in out, out + err)

# --- the exit code is honest ---------------------------------------------
print("\nexit codes")
rc, out, err = run("Get-Item C:\\definitely-not-here-9f3a")
check("a failing remote command exits 1", rc == 1, f"rc={rc} {out}{err}")
rc, out, err = run("Write-Output ok")
check("a succeeding remote command exits 0", rc == 0 and "ok" in out, out + err)

# --- built-ins are reachable (the feature) -------------------------------
print("\nbuilt-ins")
rc, out, err = run("help")
check("help prints the port's help, not the target's",
      rc == 0 and "Any PowerShell command" in out, out + err)

rc, out, err = run("services", admin=True)
# The pre-change binary sends `services` to PowerShell, which has no such
# command -- so the discriminator is a real table vs a cmdlet-not-found record.
ok = rc == 0 and "Path" in out and "not recognized" not in out
check("services returns the target's service table", ok, out + err)

rc, out, err = run(f"upload {src} {remote}")
check("upload runs as a one-shot", rc == 0 and "not recognized" not in out, out + err)

rc, out, err = run(f"(Get-FileHash -Algorithm SHA256 '{remote}').Hash")
check("the uploaded file matches the target's own hash",
      rc == 0 and want in out.upper(), f"want {want} got {out}{err}")

dst = os.path.join(tmp, "down.bin")
rc, out, err = run(f"download {remote} {dst}")
got = ""
if os.path.exists(dst):
    with open(dst, "rb") as f:
        got = hashlib.sha256(f.read()).hexdigest().upper()
check("download runs as a one-shot and round-trips", rc == 0 and got == want,
      f"want {want} got {got or 'no file'} {out}{err}")

rc, out, err = run("menu")
check("menu runs as a one-shot", rc == 0 and "not recognized" not in out, out + err)

# --- json ----------------------------------------------------------------
print("\n-o json")
rc, out, err = run("whoami", "-o", "json")
obj = None
try:
    obj = json.loads(out.strip().splitlines()[0])
except Exception as e:
    check("json output parses", False, f"{e}: {out}")
else:
    check("json output parses", True)
    check("json reports success", rc == 0 and obj.get("had_errors") is False
          and any("\\" in str(o) for o in obj.get("output", [])), json.dumps(obj)[:300])

rc, out, err = run("Get-Item C:\\definitely-not-here-9f3a", "-o", "json")
try:
    obj = json.loads(out.strip().splitlines()[0])
except Exception as e:
    check("a failing command still emits one json object", False, f"{e}: {out}")
else:
    check("a failing command still emits one json object", True)
    check("json marks it failed and exits 1",
          rc == 1 and obj.get("had_errors") is True, f"rc={rc} {json.dumps(obj)[:300]}")

# --- logging -------------------------------------------------------------
print("\n-l transcript")
logroot = os.path.join(tmp, "logs")
env = dict(os.environ, WSMANCER_LOG_DIR=logroot)
p = subprocess.run([BIN, "-i", HOST, "-u", USER, "-r", REALM, "-p", PW,
                    "-l", "-x", "whoami"], capture_output=True, text=True, env=env, timeout=180)
written = ""
for root, _, files in os.walk(logroot):
    for fn in files:
        with open(os.path.join(root, fn)) as f:
            written += f.read()
check("-l writes a one-shot transcript containing the command and its output",
      p.returncode == 0 and "whoami" in written and "\\" in written, written[:300])

# --- cleanup -------------------------------------------------------------
run(f"Remove-Item -Force '{remote}' -ErrorAction SilentlyContinue")

n, total = sum(results), len(results)
print(f"\n{n}/{total} passed")
sys.exit(0 if n == total else 1)
