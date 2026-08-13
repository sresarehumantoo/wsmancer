#!/usr/bin/env python3
"""Prove WinRM client-certificate authentication end to end.

Run scripts/certauth-setup.sh first; it configures the target and mints the two
certificate pairs this uses.

The thing that makes a cert-auth "pass" easy to fake is that the target may have
authenticated you some *other* way -- a stray Negotiate handshake, an anonymous
allowance -- and the shell would look identical. So the positive result is only
believed alongside two controls that must fail:

  * with the mapping removed, the same certificate must be refused (401). The
    harness removes and restores it, so a build that is really authenticating by
    some other means fails here.
  * a rogue certificate -- same subject, same UPN, same EKU, different CA -- must
    also be refused, which is what proves the chain is checked rather than the
    mere presence of a certificate.

The identity assertion is the mapped account ($CERTAUTH_MAP_UPN), which the
command line never names: with no -u anywhere, the only way that name can come
back from whoami is the target's own certificate mapping.

Usage: MAP_PASS=<mapped account password> scripts/certauth-test.py <admin-user> <nthash>
       (after sourcing the env.sh that certauth-setup.sh wrote)
"""
import os, pty, select, struct, subprocess, sys, termios, fcntl, time, re, signal

if len(sys.argv) != 3:
    sys.exit(__doc__)
ADMIN, HASH = sys.argv[1:3]

try:
    HOST = os.environ["CERTAUTH_HOST"]
    FP = os.environ["CERTAUTH_FP"]
    ISSUER = os.environ["CERTAUTH_ISSUER"]
    CERT, KEY = os.environ["CERTAUTH_CERT"], os.environ["CERTAUTH_KEY"]
    ROGUE, ROGUE_KEY = os.environ["CERTAUTH_ROGUE_CERT"], os.environ["CERTAUTH_ROGUE_KEY"]
    UPN = os.environ["CERTAUTH_MAP_UPN"]
    # The mapped account's password, for the one check that authenticates the
    # normal way. Required rather than defaulted: a password baked into a tracked
    # script is a password in git history forever.
    MAP_PASS = os.environ["MAP_PASS"]
except KeyError as e:
    sys.exit(f"missing {e}; source the env.sh written by certauth-setup.sh")

BIN = "./wsmancer"
MAPPED_USER = UPN.split("@")[0]          # svc-account@corp.local -> svc-account
REALM = UPN.split("@")[1]                # ...and its realm
CERT_ARGS = ["-S", "--accept-fingerprint", FP, "-c", CERT, "-k", KEY]
DSR = re.compile(rb'\x1b\[6n')
ESC_RE = re.compile(rb'\x1b\[[0-9;?]*[a-zA-Z]|\x1b[=>]|\r')

results = []
def check(name, ok, detail=""):
    results.append(ok)
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + ("" if ok else f"\n          {detail!r}"))


def run(args, timeout=120):
    p = subprocess.run([BIN, "-i", HOST] + args, capture_output=True, timeout=timeout)
    return p.stdout.decode("utf8", "replace") + p.stderr.decode("utf8", "replace")


def admin(ps):
    """Reconfigure the target, using the tool itself over NTLM."""
    return run(["-u", ADMIN, "-H", HASH, "-x", ps], timeout=180)


# ---- 1. the certificate alone authenticates, as the account it maps to ----
out = run(CERT_ARGS + ["-x", "whoami; hostname"])
check("a client certificate alone authenticates", MAPPED_USER in out.lower(), out[-300:])
# No -u was passed anywhere above: the identity can only have come from the
# target's mapping.
check("the identity comes from the target's mapping", MAPPED_USER in out.lower(), out[-300:])
check("the banner names certificate auth, not NTLM",
      "client certificate" in out and "NTLM" not in out, out[:300])

# ---- 2. a rogue certificate from an untrusted CA is refused ----
rogue = run(["-S", "--accept-fingerprint", FP, "-c", ROGUE, "-k", ROGUE_KEY, "-x", "whoami"])
check("a certificate from an untrusted CA is refused",
      MAPPED_USER not in rogue.lower(), rogue[-300:])

# ---- 3. the control: no mapping, no session ----
admin(r'Get-ChildItem WSMan:\localhost\ClientCertificate | Remove-Item -Recurse -Force')
unmapped = run(CERT_ARGS + ["-x", "whoami"])
check("with the mapping removed, the same certificate is refused",
      MAPPED_USER not in unmapped.lower(), unmapped[-300:])
check("...and it fails as an authentication failure (401)", "401" in unmapped, unmapped[-300:])

admin(f"""
  $p = ConvertTo-SecureString '{MAP_PASS}' -AsPlainText -Force
  $cred = New-Object System.Management.Automation.PSCredential('{REALM}\\{MAPPED_USER}', $p)
  New-Item -Path WSMan:\\localhost\\ClientCertificate -Subject '{UPN}' -URI * -Issuer '{ISSUER}' -Credential $cred -Force | Out-Null
  'restored'
""")
restored = run(CERT_ARGS + ["-x", "whoami"])
check("restoring the mapping restores access", MAPPED_USER in restored.lower(), restored[-300:])

# ---- 4. a certificate PLUS credentials is still the credential's mode ----
# This port can present a client certificate alongside NTLM (mutual TLS + a real
# handshake), which upstream cannot express. Adding cert auth must not have
# quietly taken that away.
both = run(["-u", MAPPED_USER, "-p", MAP_PASS, "-r", REALM] + CERT_ARGS + ["-x", "whoami"])
check("a certificate WITH a password still authenticates over NTLM",
      "NTLM" in both and MAPPED_USER in both.lower(), both[-300:])

# ---- 5. state survives across commands on this transport ----
# The token is assembled on the target so that matching it proves output rather
# than the terminal's echo of what was typed.
sess = run(CERT_ARGS + ["-x",
    r"Set-Content -Path C:\Windows\Temp\wsm-certauth.txt -Value ('CERT'+'PROBE'); "
    r"Get-Content C:\Windows\Temp\wsm-certauth.txt; "
    r"Remove-Item C:\Windows\Temp\wsm-certauth.txt"])
check("commands round-trip over the certificate transport", "CERTPROBE" in sess, sess[-300:])


# ---- 6. Ctrl-C over the certificate transport ----
# The riskiest untested behavior: this provider does not own a raw socket like
# the sealing ones, it leans on net/http with one connection per host. If that
# does not hold, the WSMan terminate goes out on a second connection and the
# server refuses it -- so Ctrl-C would hang instead of canceling.
class Term:
    def __init__(self, args):
        self.master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 50, 120, 0, 0))
        self.p = subprocess.Popen([BIN, "-i", HOST] + args, stdin=slave, stdout=slave,
                                  stderr=slave, close_fds=True,
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
                if DSR.search(c):
                    os.write(self.master, b'\x1b[24;1R')
                end = time.time() + timeout
        return self.buf

    def visible(self):
        return ESC_RE.sub(b'', self.buf).decode("utf8", "replace")

    def expect(self, pat, timeout=60):
        end = time.time() + timeout
        while time.time() < end:
            if re.search(pat, self.visible()):
                return True
            self.drain(0.3)
        return False

    def send(self, d, settle=0.4):
        os.write(self.master, d if isinstance(d, bytes) else d.encode())
        time.sleep(settle)


t = Term(CERT_ARGS)
if not t.expect(r"PS .*> ", 90):
    check("interactive shell over certificate auth", False, t.visible()[-300:])
else:
    check("interactive shell over certificate auth", True)

    # A real upload and download: transfer is the one path that pushes many
    # chunked round trips through this transport, and it verifies a SHA-256 on
    # the way, so a transport that corrupted or dropped a chunk fails here.
    payload = "/tmp/wsm-certauth-payload.txt"
    back = "/tmp/wsm-certauth-back.txt"
    with open(payload, "w") as f:
        f.write("CERTAUTH-PAYLOAD\n" * 4096)      # ~68 KB, several chunks
    t.send(f"upload {payload} C:\\Windows\\Temp\\wsm-payload.txt\r", 0.5)
    check("upload over certificate auth", t.expect(r"uploaded|Info: .*upload", 120),
          t.visible()[-300:])
    t.send(f"download C:\\Windows\\Temp\\wsm-payload.txt {back}\r", 0.5)
    check("download over certificate auth", t.expect(r"downloaded|Info: .*download", 120),
          t.visible()[-300:])
    same = os.path.exists(back) and open(back, "rb").read() == open(payload, "rb").read()
    check("the downloaded bytes match what was uploaded", same)
    for f in (payload, back):
        if os.path.exists(f):
            os.unlink(f)
    t.send("Remove-Item C:\\Windows\\Temp\\wsm-payload.txt -EA SilentlyContinue\r", 0.5)

    # The canceled command's marker is built ON THE TARGET: spelled literally it
    # would match the terminal's echo of the line as typed, and the check would
    # hold whether or not the command was actually stopped.
    t.send("Start-Sleep -Seconds 30; echo ('SHOULD-BE-' + 'CANCELED')\r", 1.5)
    t.drain(1.5)
    t.p.send_signal(signal.SIGINT)
    check("Ctrl-C cancels a running command over certificate auth",
          t.expect(r"canceling command", 30), t.visible()[-300:])
    t.send("echo ('ALIVE-' + 'AFTER')\r", 0.4)
    check("the session survives the cancel",
          t.expect(r"ALIVE-AFTER", 40) and t.p.poll() is None, t.visible()[-300:])
    check("the canceled command did not finish",
          "SHOULD-BE-CANCELED" not in t.visible(), t.visible()[-300:])
    t.send("\x04", 0.3)
    for _ in range(40):
        if t.p.poll() is not None:
            break
        t.drain(0.3)
    if t.p.poll() is None:
        t.p.kill()

print(f"\n== {sum(results)}/{len(results)} passed ==")
sys.exit(0 if all(results) else 1)
