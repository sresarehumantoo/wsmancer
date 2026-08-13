#!/usr/bin/env python3
"""Live validation of the transfer engine's edge cases against a real target.

The offline tests (internal/transfer/engine_test.go) drive an in-process *fake*
WinRM target. This script confirms the assumptions that fake encodes actually
hold on a real Server 2016 box, so the fake can't quietly drift from reality:

  - a multi-chunk upload lands byte-for-byte (checked against the *target's own*
    Get-FileHash, so a byte-splicing bug shows where the client's self-report
    could not) and a download round-trips byte-exact;
  - an empty file is still created on the target (the loop never runs, so only
    the first==true fallback writes it);
  - the first chunk opens in Create mode, which truncates an existing longer
    file on re-upload, otherwise stale tail bytes survive.

It drives the interactive shell's upload/download built-ins over piped stdin
(the shell does plain reads for a non-terminal), and forces the multi-chunk
path with --chunk-size 4 (KB). The remote working directory is created relative
to the shell's location, so no account-specific path is baked in.

Differential (per the repo's rule that a harness must be able to fail): build
the binary with writeChunk's Create replaced by Append and re-run, the three
Create-truncates checks fail (and the client's own integrity check trips),
while the multi-chunk round-trips still pass. Verified on Forest: 10/10, and
7/10 against that mutant.

Usage: transfer-edge-test.py <host> <user> <realm> <password>
       WSM_BIN overrides the binary (default ./wsmancer, run from repo root)
"""
import hashlib
import os
import subprocess
import sys
import tempfile

if len(sys.argv) != 5:
    sys.exit(__doc__)
HOST, USER, REALM, PW = sys.argv[1:5]
BIN = os.environ.get("WSM_BIN", "./wsmancer")
RSUB = "wsmtx"  # remote working dir, relative to the shell's location

results = []
def check(name, ok):
    results.append(bool(ok))
    print(f"  {'PASS' if ok else 'FAIL'}  {name}")

def sha(b):
    return hashlib.sha256(b).hexdigest().upper()

tmp = tempfile.mkdtemp(prefix="wsm-tx-")
# Deterministic-but-nontrivial payloads: any truncation or byte-swap changes the hash.
big   = bytes((i * 37 + 11) & 0xFF for i in range(50000))   # ~13 chunks at 4KB
empty = b""
longd = bytes((i * 5 + 3) & 0xFF for i in range(20000))
short = bytes((i * 9 + 1) & 0xFF for i in range(1000))
for name, data in (("big.bin", big), ("empty.txt", empty),
                   ("long.bin", longd), ("short.bin", short)):
    with open(os.path.join(tmp, name), "wb") as f:
        f.write(data)

def L(n):
    return os.path.join(tmp, n)

# One session does the whole run; the runspace persists $d across lines.
script = "\n".join([
    "$d = Join-Path (Get-Location).Path '%s'" % RSUB,
    "Remove-Item -Recurse -Force $d -ErrorAction SilentlyContinue",
    "New-Item -ItemType Directory -Force $d | Out-Null",
    "'DIRREADY'",
    # 1. multi-chunk upload; report the target's own length + hash
    f"upload {L('big.bin')} {RSUB}\\big.bin",
    '"MC:{0}:{1}" -f (Get-Item $d\\big.bin).Length,(Get-FileHash $d\\big.bin -Algorithm SHA256).Hash',
    # 2. download it straight back
    f"download {RSUB}\\big.bin {L('big.down.bin')}",
    # 3. empty file must still be created
    f"upload {L('empty.txt')} {RSUB}\\empty.txt",
    '"EMPTY:{0}:{1}" -f (Test-Path $d\\empty.txt),(Get-Item $d\\empty.txt).Length',
    # 4. Create-truncates: a long file, then a short one to the same name
    f"upload {L('long.bin')} {RSUB}\\trunc.bin",
    '"PRE:{0}" -f (Get-Item $d\\trunc.bin).Length',
    f"upload {L('short.bin')} {RSUB}\\trunc.bin",
    '"POST:{0}:{1}" -f (Get-Item $d\\trunc.bin).Length,(Get-FileHash $d\\trunc.bin -Algorithm SHA256).Hash',
    "Remove-Item -Recurse -Force $d",
    "exit",
    "",
])

print(f"== driving {HOST} (payloads in {tmp}) ==")
p = subprocess.run(
    [BIN, "-i", HOST, "-u", USER, "-r", REALM, "-p", PW, "--chunk-size", "4"],
    input=script, capture_output=True, text=True, timeout=240)
out = p.stdout + p.stderr

def marker(prefix):
    for ln in out.splitlines():
        ln = ln.strip()
        i = ln.find(prefix)
        if i != -1:
            return ln[i + len(prefix):].strip()
    return None

# Any integrity failure prints "integrity check FAILED"; a clean run never does.
check("no integrity failure reported by the client", "integrity check FAILED" not in out)
check("session reached the working dir", "DIRREADY" in out)

# 1. multi-chunk upload landed byte-exact (target's own hash == source hash)
mc = marker("MC:")
check("multi-chunk upload: target length matches source",
      mc is not None and mc.split(":")[0] == str(len(big)))
check("multi-chunk upload: target SHA-256 matches source",
      mc is not None and mc.split(":")[1].upper() == sha(big))

# 2. download round-trips byte-exact
try:
    with open(L("big.down.bin"), "rb") as f:
        got = f.read()
except FileNotFoundError:
    got = None
check("download round-trip is byte-exact", got is not None and sha(got) == sha(big))

# 3. empty file created, length 0
em = marker("EMPTY:")
check("empty file exists on target", em is not None and em.split(":")[0].lower() == "true")
check("empty file has length 0", em is not None and em.split(":")[1] == "0")

# 4. Create truncated the pre-existing longer file
pre, post = marker("PRE:"), marker("POST:")
check("pre-existing file was the long one", pre == str(len(longd)))
check("re-upload truncated to the short length",
      post is not None and post.split(":")[0] == str(len(short)))
check("re-uploaded content is the short file's (hash matches)",
      post is not None and post.split(":")[1].upper() == sha(short))

n = sum(results)
print(f"\n== {n}/{len(results)} passed ==")
sys.exit(0 if n == len(results) else 1)
