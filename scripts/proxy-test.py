#!/usr/bin/env python3
"""Prove --proxy actually routes the session through a SOCKS5 proxy.

The failure this guards against is a silent one. If the flag were wired up
wrongly the tool would not error: it would dial straight out of the attacker's
own interface and, against a target that happens to be reachable both ways,
everything would look fine. That is exactly what proxychains does to a static Go
binary today -- the LD_PRELOAD shim is never called, so the proxy is ignored
rather than refused -- and it is the reason this flag exists at all. So every
check here asserts on what the *proxy* saw, not merely that the command worked.

It runs its own SOCKS5 proxy in-process (RFC 1928/1929), recording every CONNECT.

  scripts/proxy-test.py --offline
      Checks needing no target: the dial reaches the proxy, the target's name is
      sent to it unresolved, credentials are negotiated, and a bad URL is
      refused at startup. The name used resolves nowhere, so a build that dialled
      directly cannot pass.

  sudo scripts/proxy-test.py --netns [<target-ip>]
      Isolation at the routing layer: run the client in a network namespace whose
      only reachable address is the proxy, so a direct dial gets "network is
      unreachable" and no control is needed to prove the traffic went through the
      proxy -- the wrong answer is physically forbidden. Needs no target (a dummy
      interface stands in) but needs root for `ip netns`, hence sudo. This closes
      the routing weakness the --offline checks have on DNS but not on routing.

  scripts/proxy-test.py <host> <user> <realm> <password>
      The above plus a real session through the proxy: authentication, sealing
      and a command whose answer is computed on the target. Includes the control
      that matters -- with the proxy refusing, the same session must fail, or
      "it worked through the proxy" would not mean the traffic went through it.
      Also drives the three paths a real tunnel exercises that a one-shot does
      not: a file upload/download round-trip, an out-of-band Ctrl-C, and an idle
      session (WSMANCER_PROXY_IDLE overrides the idle seconds, default 35).

      --hash <nthash>     also prove pass-the-hash through the proxy
      --ticket <ccache>   also prove Kerberos -- krbseal has its own dial site,
                          and an NTLM-only run leaves it untested
      --skew <seconds>    passed to --skew for the Kerberos run (lab DC clocks)
      --tls-fingerprint <sha256>
                          also prove the HTTPS/5986 paths, which is the only way
                          proxydial.DialTLS is reached at all. Needs a target
                          with an HTTPS listener -- certauth-setup.sh stands one
                          up and prints the fingerprint
      --cert/--key <path> also prove certificate auth, the fourth dial site

Usage: scripts/proxy-test.py [--offline | <host> <user> <realm> <password>
                              [--hash H] [--ticket PATH] [--skew N]]
"""
import fcntl
import hashlib
import os
import pty
import re
import select
import socket
import struct
import subprocess
import sys
import tempfile
import termios
import threading
import time

BIN = os.environ.get(
    "WSMANCER_TEST_BIN",
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "wsmancer"),
)

# A name with no answer in any resolver: RFC 6761 reserves .invalid precisely so
# it can never resolve. If the tool resolved locally instead of at the proxy,
# the dial fails here rather than quietly working.
UNRESOLVABLE = "dc01.internal.invalid"

ATYP_IPV4, ATYP_DOMAIN, ATYP_IPV6 = 1, 3, 4

results = []


def check(name, ok, detail=""):
    results.append((name, ok))
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
    if not ok and detail:
        print(f"         {detail}")


class SocksProxy:
    """A minimal SOCKS5 proxy that records what it was asked to connect to.

    refuse=True answers every CONNECT with a failure reply, which is how the
    control below proves the session really depends on the proxy.
    """

    def __init__(self, auth=None, refuse=False, bind_host="127.0.0.1", bind_port=0):
        self.auth = auth              # (user, pass) or None
        self.refuse = refuse
        self.bind_host = bind_host    # 10.99.0.1 for the netns mode, loopback otherwise
        self.requests = []            # (atyp, host, port)
        self.lock = threading.Lock()
        self.srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind((bind_host, bind_port))
        self.srv.listen(16)
        self.port = self.srv.getsockname()[1]
        self.stop = False
        threading.Thread(target=self._accept, daemon=True).start()

    @property
    def url(self):
        if self.auth:
            return f"socks5://{self.auth[0]}:{self.auth[1]}@{self.bind_host}:{self.port}"
        return f"socks5://{self.bind_host}:{self.port}"

    def seen(self):
        with self.lock:
            return list(self.requests)

    def close(self):
        self.stop = True
        try:
            self.srv.close()
        except OSError:
            pass

    def _accept(self):
        while not self.stop:
            try:
                c, _ = self.srv.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(c,), daemon=True).start()

    def _recv(self, s, n):
        buf = b""
        while len(buf) < n:
            b = s.recv(n - len(buf))
            if not b:
                raise ConnectionError("short read")
            buf += b
        return buf

    def _handle(self, c):
        up = None
        try:
            ver, nm = self._recv(c, 2)
            methods = self._recv(c, nm)
            if self.auth:
                if 2 not in methods:
                    c.sendall(b"\x05\xff")
                    return
                c.sendall(b"\x05\x02")
                self._recv(c, 1)                       # auth version
                user = self._recv(c, self._recv(c, 1)[0])
                pw = self._recv(c, self._recv(c, 1)[0])
                if (user.decode(), pw.decode()) != self.auth:
                    c.sendall(b"\x01\x01")
                    return
                c.sendall(b"\x01\x00")
            else:
                c.sendall(b"\x05\x00")

            _ver, _cmd, _rsv, atyp = self._recv(c, 4)
            if atyp == ATYP_IPV4:
                host = socket.inet_ntoa(self._recv(c, 4))
            elif atyp == ATYP_IPV6:
                host = socket.inet_ntop(socket.AF_INET6, self._recv(c, 16))
            elif atyp == ATYP_DOMAIN:
                host = self._recv(c, self._recv(c, 1)[0]).decode()
            else:
                return
            port = int.from_bytes(self._recv(c, 2), "big")
            with self.lock:
                self.requests.append((atyp, host, port))

            if self.refuse:
                c.sendall(b"\x05\x05\x00\x01" + b"\x00" * 6)
                return
            try:
                up = socket.create_connection((host, port), timeout=10)
            except OSError:
                c.sendall(b"\x05\x05\x00\x01" + b"\x00" * 6)
                return
            c.sendall(b"\x05\x00\x00\x01" + b"\x00" * 6)
            self._splice(c, up)
        except (ConnectionError, OSError, IndexError):
            pass
        finally:
            for s in (c, up):
                try:
                    if s:
                        s.close()
                except OSError:
                    pass

    def _splice(self, a, b):
        def pump(src, dst):
            try:
                while True:
                    data = src.recv(65536)
                    if not data:
                        break
                    dst.sendall(data)
            except OSError:
                pass
            finally:
                try:
                    dst.shutdown(socket.SHUT_WR)
                except OSError:
                    pass

        t = threading.Thread(target=pump, args=(a, b), daemon=True)
        t.start()
        pump(b, a)
        t.join(timeout=5)


def run(args, timeout=90, env=None):
    e = dict(os.environ)
    e.pop("WSMANCER_PROXY", None)      # never inherit one; these tests set it
    if env:
        e.update(env)
    p = subprocess.run([BIN] + args, capture_output=True, text=True, timeout=timeout, env=e)
    return p.returncode, p.stdout + p.stderr


def offline_checks():
    print("== offline: the dial reaches the proxy ==")

    # 1. A dial for a name that resolves nowhere still reaches the proxy, and
    #    reaches it as a *name*. The connection then fails (the proxy cannot
    #    resolve it either) -- irrelevant: what is asserted is what the proxy saw.
    px = SocksProxy()
    rc, out = run(["-i", UNRESOLVABLE, "-u", "a", "-p", "b", "--proxy", px.url,
                   "-x", "whoami"], timeout=60)
    seen = px.seen()
    px.close()
    check("the proxy saw a CONNECT for the target",
          any(h == UNRESOLVABLE and p == 5985 for _a, h, p in seen), f"saw {seen}")
    check("the target's name was sent unresolved (socks5h)",
          any(a == ATYP_DOMAIN and h == UNRESOLVABLE for a, h, _p in seen), f"saw {seen}")
    # The banner is a claim about what the tool intends, not evidence of what it
    # did -- it still prints on a build that dials direct. It is checked because
    # the operator relies on it, not because it proves anything above.
    check("the banner says the connection is proxied",
          "via socks5 127.0.0.1:" in out, repr(out[:400]))

    # 2. The control for check 1: without --proxy the same run must touch no
    #    proxy at all. Without this, a build that dialled directly *and* happened
    #    to reach a proxy for other reasons would look identical.
    px = SocksProxy()
    rc, out = run(["-i", UNRESOLVABLE, "-u", "a", "-p", "b", "-x", "whoami"], timeout=60)
    seen = px.seen()
    px.close()
    check("without --proxy the proxy sees nothing", seen == [], f"saw {seen}")
    check("without --proxy the name is resolved locally, and fails",
          "no such host" in out.lower() or "lookup" in out.lower(), repr(out[-300:]))

    # 3. Credentials in the URL are negotiated. The proxy demands user/pass, so a
    #    build that dropped them never gets as far as a CONNECT.
    px = SocksProxy(auth=("op", "s3cr3t"))
    run(["-i", UNRESOLVABLE, "-u", "a", "-p", "b", "--proxy", px.url, "-x", "whoami"], timeout=60)
    seen = px.seen()
    px.close()
    check("proxy credentials are negotiated", len(seen) > 0,
          "the proxy required user/pass and saw no CONNECT")

    # 4. And the negative half: a wrong password must not get through, or check 3
    #    would pass just as well against a proxy that ignored what it was sent.
    #    Note this one is vacuous on its own -- a build that ignored --proxy
    #    entirely also reaches no CONNECT -- so it means something only alongside
    #    check 3. Measured: against a binary whose dialer always goes direct,
    #    checks 1, 2, 3 and 6 fail and this one still passes.
    px = SocksProxy(auth=("op", "s3cr3t"))
    bad = px.url.replace(":s3cr3t@", ":wrong@")
    run(["-i", UNRESOLVABLE, "-u", "a", "-p", "b", "--proxy", bad, "-x", "whoami"], timeout=60)
    seen = px.seen()
    px.close()
    check("a wrong proxy password is refused", seen == [], f"saw {seen}")

    # 5. A bad URL fails at startup, before anything dials.
    rc, out = run(["-i", "10.0.0.1", "-u", "a", "-p", "b",
                   "--proxy", "http://127.0.0.1:8080", "-x", "whoami"], timeout=30)
    check("an unsupported proxy scheme is refused at startup",
          rc != 0 and "socks5" in out, f"rc={rc} {out[:200]!r}")

    # 6. The environment variable is honoured, so an engagement can export one.
    px = SocksProxy()
    run(["-i", UNRESOLVABLE, "-u", "a", "-p", "b", "-x", "whoami"], timeout=60,
        env={"WSMANCER_PROXY": px.url})
    seen = px.seen()
    px.close()
    check("$WSMANCER_PROXY is honoured", len(seen) > 0, f"saw {seen}")


def skip(name, why):
    print(f"  [SKIP] {name}, {why}")


def other_auth_checks(host, realm, nthash, ticket, skew):
    """Pass-the-hash and Kerberos through the proxy.

    Worth their own checks because --proxy touches *four* dial sites, and a
    session proved over NTLM-password exercises only one of them. Kerberos is a
    different provider (krbseal) with its own dial, and pass-the-hash, while the
    same provider, is the mode an operator actually pivots with.

    Both are optional: they need a hash and a ticket this repo deliberately does
    not carry. Skipped loudly rather than passed quietly when absent.
    """
    print("\n== live: the other auth paths through the proxy ==")

    if not nthash:
        skip("pass-the-hash through the proxy", "no --hash given")
    else:
        px = SocksProxy()
        rc, out = run(["-i", host, "-u", "Administrator", "-r", realm,
                       "-H", nthash, "--proxy", px.url, "-x", "'PTH' + '-OK'"])
        seen = px.seen()
        px.close()
        check("pass-the-hash runs through the proxy",
              rc == 0 and "PTH-OK" in out and any(h == host for _a, h, _p in seen),
              f"rc={rc} saw={seen} {out[-200:]!r}")

        px = SocksProxy(refuse=True)
        rc, out = run(["-i", host, "-u", "Administrator", "-r", realm,
                       "-H", nthash, "--proxy", px.url, "-x", "'PTH' + '-OK'"])
        px.close()
        check("a refusing proxy breaks pass-the-hash (control)",
              rc != 0 and "PTH-OK" not in out, f"rc={rc} {out[-200:]!r}")

    if not ticket:
        skip("kerberos through the proxy", "no --ticket given (scripts/get-tickets.sh mints one)")
    else:
        args = ["-i", host, "-K", ticket, "-r", realm]
        if skew:
            args += ["--skew", str(skew)]
        px = SocksProxy()
        rc, out = run(args + ["--proxy", px.url, "-x", "'KRB' + '-OK'"])
        seen = px.seen()
        px.close()
        check("kerberos runs through the proxy (krbseal's own dial site)",
              rc == 0 and "KRB-OK" in out and any(h == host for _a, h, _p in seen),
              f"rc={rc} saw={seen} {out[-200:]!r}")

        px = SocksProxy(refuse=True)
        rc, out = run(args + ["--proxy", px.url, "-x", "'KRB' + '-OK'"])
        px.close()
        check("a refusing proxy breaks kerberos (control)",
              rc != 0 and "KRB-OK" not in out, f"rc={rc} {out[-200:]!r}")


def tls_checks(host, user, realm, password, fp, cert, key, ticket, skew):
    """The HTTPS/5986 paths through the proxy.

    These matter more than their count suggests. Everything above runs over 5985,
    where the proxied connection carries plain HTTP -- so proxydial.DialTLS, the
    riskiest part of this feature, is never reached. It is what replaced
    tls.DialWithDialer (which cannot be pointed at a proxy) for the two sealing
    providers, and it owns the ServerName defaulting that certificate
    verification depends on.

    Pinning by fingerprint is deliberate rather than incidental: it only succeeds
    if verification ran against the *target's* certificate. A tunnel that
    verified the proxy, or skipped verification, cannot produce it.

    certauth is the fourth and last dial site, and the odd one -- it hands the
    dialer to an http.Transport, which layers TLS itself, so it exercises
    DialContext rather than DialTLS, plus Schannel's renegotiation through the
    tunnel.

    Needs a target with an HTTPS listener: scripts/certauth-setup.sh stands one
    up (and tears it down again). Skipped loudly when not given.
    """
    print("\n== live: HTTPS/5986 through the proxy ==")
    if not fp:
        skip("TLS through the proxy", "no --tls-fingerprint given (certauth-setup.sh prints one)")
        return

    tls_base = ["-i", host, "-S", "--accept-fingerprint", fp]
    probe = "'TLS' + '-OK'"

    for label, creds in (
        ("NTLM password", ["-u", user, "-r", realm, "-p", password]),
        ("kerberos", (["-K", ticket, "-r", realm] + (["--skew", str(skew)] if skew else [])) if ticket else None),
    ):
        if creds is None:
            skip(f"{label} over TLS through the proxy", "no --ticket given")
            continue
        px = SocksProxy()
        rc, out = run(tls_base + creds + ["--proxy", px.url, "-x", probe])
        seen = px.seen()
        px.close()
        check(f"{label} over TLS through the proxy, pinned to the target's cert",
              rc == 0 and "TLS-OK" in out and any(h == host and p == 5986 for _a, h, p in seen),
              f"rc={rc} saw={seen} {out[-200:]!r}")

        px = SocksProxy(refuse=True)
        rc, out = run(tls_base + creds + ["--proxy", px.url, "-x", probe])
        px.close()
        check(f"a refusing proxy breaks {label} over TLS (control)",
              rc != 0 and "TLS-OK" not in out, f"rc={rc} {out[-200:]!r}")

    if not (cert and key):
        skip("certificate auth through the proxy", "no --cert/--key given")
        return
    px = SocksProxy()
    rc, out = run(tls_base + ["-c", cert, "-k", key, "--proxy", px.url, "-x", "'CERT' + '-OK'"])
    seen = px.seen()
    px.close()
    check("certificate auth through the proxy (certauth's http.Transport dial)",
          rc == 0 and "CERT-OK" in out and any(h == host and p == 5986 for _a, h, p in seen),
          f"rc={rc} saw={seen} {out[-200:]!r}")

    px = SocksProxy(refuse=True)
    rc, out = run(tls_base + ["-c", cert, "-k", key, "--proxy", px.url, "-x", "'CERT' + '-OK'"])
    px.close()
    check("a refusing proxy breaks certificate auth (control)",
          rc != 0 and "CERT-OK" not in out, f"rc={rc} {out[-200:]!r}")


def live_checks(host, user, realm, password):
    print(f"\n== live: a real session through the proxy ({host}) ==")

    # The token is concatenated on the target, so matching it proves the command
    # ran there -- an echo of what was typed cannot satisfy it.
    probe = "'PROX' + 'IED'"

    px = SocksProxy()
    rc, out = run(["-i", host, "-u", user, "-r", realm, "-p", password,
                   "--proxy", px.url, "-x", probe])
    seen = px.seen()
    px.close()
    check("a command runs through the proxy", rc == 0 and "PROXIED" in out,
          f"rc={rc} {out[-300:]!r}")
    check("the proxy carried that session",
          any(h == host and p == 5985 for _a, h, p in seen), f"saw {seen}")

    # The control. If this passed too, the checks above would prove nothing about
    # where the traffic went: a refusing proxy must break the session.
    px = SocksProxy(refuse=True)
    rc, out = run(["-i", host, "-u", user, "-r", realm, "-p", password,
                   "--proxy", px.url, "-x", probe])
    px.close()
    check("a refusing proxy breaks the session (control)",
          rc != 0 and "PROXIED" not in out, f"rc={rc} {out[-300:]!r}")

    # A large sealed response, intact, through the proxy. Every check above
    # proves the seal survives at all -- the listener runs AllowUnencrypted=false,
    # so unsealed traffic is faulted, and a command that answered at all was
    # sealed. What this adds is *volume*: a reply far bigger than one packet,
    # spanning several reads and RC4 seal blocks, which is where a byte-splicing
    # bug in the tunnel would show up and a one-line answer never would.
    #
    # It counts the payload rather than lines. Line counting was the first
    # version and was wrong twice over: the two banner lines alone nearly
    # satisfied it, and the cmdlet it used (Get-Service) needs privileges this
    # account does not have, so it measured permissions rather than transport.
    size = 200_000
    px = SocksProxy()
    rc, out = run(["-i", host, "-u", user, "-r", realm, "-p", password,
                   "--proxy", px.url, "-x", f"'A' * {size}"])
    px.close()
    got = out.count("A")
    check(f"a large sealed response ({size // 1000} KB) survives the proxy intact",
          rc == 0 and got >= size, f"rc={rc} got {got} of {size} bytes")

    # -o json through the proxy: the structured path is a different render, same
    # transport, and it is what an automated caller uses.
    px = SocksProxy()
    rc, out = run(["-i", host, "-u", user, "-r", realm, "-p", password,
                   "--proxy", px.url, "-o", "json", "-x", probe])
    px.close()
    check("-o json works through the proxy", rc == 0 and "PROXIED" in out and '"' in out,
          f"rc={rc} {out[-300:]!r}")


# --- tunnel paths: what a real proxy exercises that a one-shot -x does not --
#
# Everything above proves a single request-response goes through the proxy. Three
# paths only a driven interactive session reaches differ over a real tunnel from
# over the loopback splice these tests used to stop at: a file transfer (far the
# most round trips of anything here, and where a byte-splicing bug in the tunnel
# would show), an out-of-band Ctrl-C (StopPipelines has to reach the shell over
# the *same* proxied connection), and a session left idle (the Receive long-poll
# cycling across the tunnel). They drive the shell through a PTY, the same way
# ctrlc-latency.py / pty-test.py do, and every one still asserts the proxy
# carried the session.

ESC_RE = re.compile(rb'\x1b\[[0-9;?]*[a-zA-Z]|\x1b[=>]|\r')
DSR = re.compile(rb'\x1b\[6n')          # the editor's cursor-position query
PROMPT = r"PS [^\n]*> "


class ShellPTY:
    """Drive the interactive shell through a PTY, answering the editor's DSR.

    A bare PTY has nothing to answer reeflective's ESC[6n cursor query, so the
    reader would block and look exactly like a transport hang -- the DSR trap
    documented in docs/verification.md. Both read loops answer it.
    """

    def __init__(self, args):
        self.master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 50, 120, 0, 0))
        e = dict(os.environ, TERM="xterm-256color")
        e.pop("WSMANCER_PROXY", None)
        self.p = subprocess.Popen([BIN] + args, stdin=slave, stdout=slave,
                                  stderr=slave, env=e, close_fds=True)
        os.close(slave)
        self.buf = b""

    def _pump(self, c):
        self.buf += c
        if DSR.search(c):
            os.write(self.master, b'\x1b[24;1R')

    def expect(self, pat, timeout=60.0, tick=0.02):
        end = time.time() + timeout
        while time.time() < end:
            r, _, _ = select.select([self.master], [], [], tick)
            if r:
                try:
                    c = os.read(self.master, 65536)
                except OSError:
                    return None
                if c:
                    self._pump(c)
            if re.search(pat, self.visible()):
                return time.time()
        return None

    def drain(self, secs):
        end = time.time() + secs
        while time.time() < end:
            r, _, _ = select.select([self.master], [], [], 0.05)
            if r:
                try:
                    c = os.read(self.master, 65536)
                except OSError:
                    return
                if c:
                    self._pump(c)

    def send(self, s):
        os.write(self.master, s.encode() if isinstance(s, str) else s)

    def clear(self):
        self.drain(0.2)
        self.buf = b""

    def visible(self):
        return ESC_RE.sub(b'', self.buf).decode("utf8", "replace")

    def sigint(self):
        os.kill(self.p.pid, 2)          # real SIGINT; no controlling tty here

    def close(self):
        # Like the other PTY harnesses here (ctrlc-latency.py, pty-test.py), just
        # kill: wsmancer's exit closes the client without a WSMan shell
        # Delete, so the server-side shell lingers either way until the PT30M idle
        # timeout. lab/README documents that as expected test litter.
        try:
            self.p.kill()
        except OSError:
            pass


def tunnel_path_checks(host, user, realm, password):
    print("\n== live: the paths a real tunnel exercises ==")
    creds = ["-i", host, "-u", user, "-r", realm, "-p", password]
    remote = r"C:\Windows\Temp\ewt-proxy-tunnel.bin"

    # --- 1. upload + download round-trip through the proxy ---
    # A payload big enough to span many transfer chunks (each rides as base64
    # inside PowerShell), so a tunnel that dropped or duplicated bytes would
    # corrupt the SHA-256 the transfer verifies -- and, independently, the remote
    # Get-FileHash below. A one-line command could never show that.
    px = SocksProxy()
    tmp = tempfile.mkdtemp(prefix="ewt-proxy-")
    src = os.path.join(tmp, "src.bin")
    dst = os.path.join(tmp, "back.bin")
    payload = bytes((i * 131 + 7) & 0xFF for i in range(300_000))  # 300 KB, no RNG needed
    with open(src, "wb") as f:
        f.write(payload)
    want = hashlib.sha256(payload).hexdigest().upper()

    t = ShellPTY(creds + ["--proxy", px.url])
    try:
        if not t.expect(PROMPT, 60):
            check("upload/download: shell connected through the proxy", False,
                  "never got a prompt:\n" + t.visible()[-800:])
        else:
            t.clear()
            t.send(f"upload {src} '{remote}'\r")
            up = t.expect(r"upload complete", 90)
            check("upload completes through the proxy", up is not None,
                  t.visible()[-500:])
            # Prove the bytes are intact on the target, not merely that the tool
            # reported success -- the hash is computed on the far side and echoed.
            t.clear()
            t.send(f"(Get-FileHash '{remote}' -Algorithm SHA256).Hash\r")
            check("the uploaded file's hash matches on the target",
                  t.expect(re.escape(want), 30) is not None,
                  f"want {want}\n{t.visible()[-500:]}")
            # And back down again; compare the returned file to the original.
            t.clear()
            t.send(f"download '{remote}' {dst}\r")
            down = t.expect(r"download complete", 90)
            got = hashlib.sha256(open(dst, "rb").read()).hexdigest().upper() if os.path.exists(dst) else "(missing)"
            check("download returns the same bytes through the proxy",
                  down is not None and got == want, f"want {want} got {got}")
            check("the transfer session was carried by the proxy",
                  any(h == host and p == 5985 for _a, h, p in px.seen()), f"saw {px.seen()}")
            t.clear()
            t.send(f"Remove-Item '{remote}' -Force -ErrorAction SilentlyContinue\r")
            t.expect(PROMPT, 15)
    finally:
        t.close()
        px.close()
        for f in (src, dst):
            try:
                os.remove(f)
            except OSError:
                pass
        try:
            os.rmdir(tmp)
        except OSError:
            pass

    # --- 2. Ctrl-C reaches the shell over the proxied connection ---
    # StopPipelines terminates the running command over the same connection that
    # owns the shell (WinRM locks a shell to one client). This is a correctness
    # check, not the latency benchmark ctrlc-latency.py runs: does the terminate
    # get there at all through the tunnel, and does the shell recover.
    px = SocksProxy()
    t = ShellPTY(creds + ["--proxy", px.url])
    try:
        if not t.expect(PROMPT, 60):
            check("ctrl-c: shell connected through the proxy", False,
                  t.visible()[-800:])
        else:
            t.clear()
            t.send("Start-Sleep -Seconds 60\r")
            time.sleep(3.0)             # let it be genuinely mid-command
            t.clear()
            t0 = time.time()
            t.sigint()
            back = t.expect(PROMPT, 20)
            check("ctrl-c through the proxy returns the prompt",
                  back is not None, "prompt never came back after SIGINT")
            # Usable, not just redrawn: with MaxRunspaces=1 the next command can
            # queue behind a still-dying pipeline. Token built on the target so the
            # terminal's echo of what was typed cannot satisfy it.
            t.clear()
            t.send('echo ("PROX"+"ALIVE")\r')
            check("the shell is usable again after a proxied ctrl-c",
                  t.expect(r"PROXALIVE", 30) is not None, t.visible()[-500:])
            check("the ctrl-c session was carried by the proxy",
                  any(h == host and p == 5985 for _a, h, p in px.seen()), f"saw {px.seen()}")
            if back is not None:
                print(f"         (prompt returned {back - t0:.2f}s after SIGINT, through the tunnel)")
    finally:
        t.close()
        px.close()

    # --- 3. an idle session survives through the proxy ---
    # The Receive long-poll cycles across the tunnel while nothing is typed. On a
    # loopback proxy there is no idle timeout to trip, so this proves the session
    # and its polling survive an idle gap through the proxy -- not the interaction
    # with a tunnel that drops idle flows, which is the blackhole case
    # connection-break-test.py covers and deadCommsBackstop exists for.
    idle = int(os.environ.get("WSMANCER_PROXY_IDLE", "35"))
    px = SocksProxy()
    t = ShellPTY(creds + ["--proxy", px.url])
    try:
        if not t.expect(PROMPT, 60):
            check("idle: shell connected through the proxy", False, t.visible()[-800:])
        else:
            t.clear()
            t.send('echo ("IDLE"+"START")\r')
            t.expect(r"IDLESTART", 30)
            t.expect(PROMPT, 15)
            print(f"         (idling {idle}s through the tunnel ...)", flush=True)
            t.drain(idle)
            t.clear()
            t.send('echo ("IDLE"+"OK")\r')
            check(f"a command runs after {idle}s idle through the proxy",
                  t.expect(r"IDLEOK", 30) is not None, t.visible()[-500:])
            check("the idle session was carried by the proxy",
                  any(h == host and p == 5985 for _a, h, p in px.seen()), f"saw {px.seen()}")
    finally:
        t.close()
        px.close()


# --- netns mode: make a direct dial physically impossible ------------------
#
# Everything above asserts on what the proxy *saw*. Against a target reachable
# both ways -- as the lab box was -- "it worked through the proxy" is also
# consistent with the proxy being ignored, and only the refusing-proxy control
# rules that out. That control is a written assertion, not a property of the
# setup: someone had to remember it.
#
# This mode removes the ambiguity at the routing layer. The client runs in a
# network namespace whose *only* reachable address is the proxy's, so a build
# that dialled direct cannot reach the target at all -- it gets "network is
# unreachable" and the proxy records no CONNECT. No control is needed because
# the wrong answer is physically forbidden, not merely unused.
#
# It needs no target: a dummy interface on the host, unreachable from inside the
# namespace but local to the proxy, stands in for the WinRM box. (Pass a real
# target IP to point it at a live box instead; the isolation is the same.) It
# does need root for `ip netns`, so it is opt-in -- run the whole script under
# sudo with --netns.
NETNS = "ewt-pivot"
HOST_ADDR = "10.99.0.1"          # host end of the veth; the proxy listens here
NS_ADDR = "10.99.0.2"            # the namespace's only address
VETH_HOST, VETH_NS = "ewt-veth0", "ewt-veth1"
DUMMY = "ewt-tgt0"
DUMMY_TARGET = "10.200.0.1"      # stand-in target: local to the host, off-net to the namespace
PROXY_PORT = 1080
TARGET_PORT = 5985


def ip(*args, check=True):
    p = subprocess.run(["ip", *args], capture_output=True, text=True)
    if check and p.returncode != 0:
        raise RuntimeError(f"ip {' '.join(args)} failed: {p.stderr.strip()}")
    return p.returncode


def netns_teardown():
    # Deleting the namespace takes its veth peer with it (and a veth pair dies
    # with either end), but delete both ends and the dummy explicitly and ignore
    # errors, so a half-built setup from a crashed run still cleans up.
    ip("netns", "del", NETNS, check=False)
    ip("link", "del", VETH_HOST, check=False)
    ip("link", "del", DUMMY, check=False)


def netns_setup(use_dummy):
    netns_teardown()             # clear any leftover from a crashed run
    ip("netns", "add", NETNS)
    ip("link", "add", VETH_HOST, "type", "veth", "peer", "name", VETH_NS, "netns", NETNS)
    ip("addr", "add", f"{HOST_ADDR}/30", "dev", VETH_HOST)
    ip("link", "set", VETH_HOST, "up")
    ip("-n", NETNS, "addr", "add", f"{NS_ADDR}/30", "dev", VETH_NS)
    ip("-n", NETNS, "link", "set", VETH_NS, "up")
    ip("-n", NETNS, "link", "set", "lo", "up")
    # Deliberately no default route inside the namespace: the /30 to HOST_ADDR is
    # the only route there is, so anything else is unreachable.
    if use_dummy:
        # A stand-in target that the proxy (on the host) can reach as a local
        # address, but the namespace cannot -- it is on no route the namespace
        # holds. Nothing listens on it; the proxy's connect is refused instantly,
        # which is all the positive check needs (it asserts on the CONNECT, not
        # on the session).
        ip("link", "add", DUMMY, "type", "dummy")
        ip("addr", "add", f"{DUMMY_TARGET}/32", "dev", DUMMY)
        ip("link", "set", DUMMY, "up")


def netns_run(args, timeout=60):
    e = dict(os.environ)
    e.pop("WSMANCER_PROXY", None)
    cmd = ["ip", "netns", "exec", NETNS, BIN, *args]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=e)
    return p.returncode, p.stdout + p.stderr


def netns_checks(target):
    print("== netns: a direct dial is physically impossible ==")
    if os.geteuid() != 0:
        sys.exit("--netns needs root for `ip netns`, run the whole script under sudo")

    use_dummy = target is None
    tgt = DUMMY_TARGET if use_dummy else target
    try:
        netns_setup(use_dummy)
        px = SocksProxy(bind_host=HOST_ADDR, bind_port=PROXY_PORT)

        # 1. Control for the isolation itself: from inside the namespace, without a
        #    proxy, the target is simply not reachable. This is what makes the
        #    positive check below unfakeable -- a build that ignored --proxy would
        #    dial direct and hit exactly this wall.
        rc, out = netns_run(["-i", tgt, "-u", "a", "-p", "b", "-x", "whoami"])
        check("without --proxy the namespace cannot reach the target at all",
              rc != 0 and "unreachable" in out.lower(), f"rc={rc} {out[-300:]!r}")
        check("and a direct dial reaches no proxy", px.seen() == [], f"saw {px.seen()}")

        # 2. The positive property: with --proxy, the same run reaches the target
        #    -- and it can only have done so through the proxy, since #1 proves
        #    there is no other path out. The session itself fails (the stand-in is
        #    not a WinRM server); what is asserted is that the proxy carried the
        #    dial, exactly as everywhere else in this file.
        proxy_url = f"socks5://{HOST_ADDR}:{PROXY_PORT}"
        rc, out = netns_run(["-i", tgt, "-u", "a", "-p", "b", "--proxy", proxy_url, "-x", "whoami"])
        seen = px.seen()
        check("with --proxy the dial reaches the target through the proxy",
              any(h == tgt and p == TARGET_PORT for _a, h, p in seen), f"saw {seen} rc={rc}")
        # No refusing-proxy control here, on purpose: #1 already established the
        # namespace has no direct route, so a passing #2 could not have bypassed
        # the proxy. The environment forbids the wrong answer.
        px.close()
    finally:
        netns_teardown()


def main():
    if not os.path.exists(BIN):
        sys.exit(f"{BIN} not found, run: go build -o wsmancer ./cmd/wsmancer")

    argv, opt = [], {"--hash": None, "--ticket": None, "--skew": None,
                     "--tls-fingerprint": None, "--cert": None, "--key": None}
    it = iter(sys.argv[1:])
    for a in it:
        if a in opt:
            opt[a] = next(it, None)
        else:
            argv.append(a)

    if argv == ["--offline"]:
        offline_checks()
    elif argv[:1] == ["--netns"]:
        # --netns            stand-in target on a dummy interface (no box needed)
        # --netns <ip>       point the isolation at a real target instead
        netns_checks(argv[1] if len(argv) > 1 else None)
    elif len(argv) == 4:
        offline_checks()
        live_checks(*argv)
        tunnel_path_checks(*argv)
        other_auth_checks(argv[0], argv[2], opt["--hash"], opt["--ticket"], opt["--skew"])
        tls_checks(argv[0], argv[1], argv[2], argv[3], opt["--tls-fingerprint"],
                   opt["--cert"], opt["--key"], opt["--ticket"], opt["--skew"])
    else:
        sys.exit(__doc__)

    failed = [r for r in results if not r[1]]
    print(f"\n== {len(results) - len(failed)}/{len(results)} passed ==")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
