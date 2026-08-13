# The verification harnesses

These are the live-target scripts behind this project's correctness claims.
`docs/verification.md` is the catalog, what each one proves, the traps it had
to learn, and the differential (a deliberately broken build) that showed it can
fail. This file is the short version: how to point them at **your** box.

Two of them need no target and run in CI: `ntlmseal-mutants.sh` and
`krbseal-mutants.sh` (`make mutants`). Everything else wants a real WinRM
listener, and assumes a locked-down one, `AllowUnencrypted=false` on HTTP/5985.
Against a permissive box most of these pass for the wrong reason, which is why
`verify-matrix.sh` runs two must-fail controls before anything else.

## Nothing here is pinned to one box

Every target, account and credential comes from the environment or the command
line. There are no credentials in this directory and no default that would work
against anyone's target but your own, a harness that named a box would rot the
day that box changed, and a harness with a baked-in password would be a leak.

State that a run produces (tickets, the measured clock skew, the rendered krb5
configs) is written to `lab/` at the repo root, which `.gitignore` excludes
whole. It is yours, and it is not part of this repo.

## Environment

| Variable | Used by | What it is |
| --- | --- | --- |
| `MXUSER` / `MXDOMAIN` / `MXPASS` | `verify-matrix.sh` | the account the matrix authenticates as |
| `MXHASH` | `verify-matrix.sh` | NT hash for the pass-the-hash row (of `MXADMIN`) |
| `MXADMIN` | `verify-matrix.sh` | privileged account for the PtH + AES rows (default `Administrator`) |
| `MXCCACHE` / `MXCCACHE_AES` / `MXKRB5CONF` | `verify-matrix.sh` | the Kerberos inputs; default to what `get-tickets.sh` writes into `lab/` |
| `KRBUSER` / `KRBPASS` | `get-tickets.sh` | `realm/user` whose TGT to mint, and its password |
| `NT` / `AES` | `get-tickets.sh` | the privileged account's NT hash and aes256 key |
| `TARGET` | `get-tickets.sh` | the host the service tickets are minted for |
| `ADMINUSER` | `get-tickets.sh` | account for the AES ticket (default `<realm>/Administrator`) |
| `MAP_USER` / `MAP_UPN` / `MAP_PASS` | `certauth-setup.sh`, `certauth-test.py` | the account a client certificate maps to |
| `WSM_WHOAMI` / `WSM_HOMEDIR` | `pty-test.py` | overrides for the derived `whoami` answer and a writable remote directory |
| `WSM_BIN` | several | the binary under test (default `./wsmancer`, run from the repo root) |
| `WSM_ADMIN_HASH` | `oneshot-test.py` | runs the `services` row privileged; an ordinary account cannot open the SCM |

`krb5.conf.tmpl` and `krb5-aes.conf.tmpl` are templates, not configs:
`get-tickets.sh` renders them into `lab/` with your realm and KDC. Nobody's realm
is committed, and no run leaves the tree dirty.

## A typical run

```sh
make build sealcheck

# Kerberos tickets first, this prints the MXCCACHE* values the matrix wants.
KRBUSER=corp.local/svc-account KRBPASS='...' \
NT=<admin nt hash> AES=<admin aes256 key> TARGET=dc01.corp.local \
  ./scripts/get-tickets.sh 10.10.10.5

MXUSER=svc-account MXDOMAIN=corp.local MXPASS='...' MXHASH=<admin nt hash> \
  ./scripts/verify-matrix.sh dc01.corp.local 10.10.10.5

./scripts/pty-test.py dc01.corp.local svc-account corp.local '...'
```

Requirements beyond the Go toolchain: `impacket` and `faketime` for
`get-tickets.sh`, `nmap` for the clock-skew probe both it and `verify-matrix.sh`
do, `openssl` for `certauth-setup.sh`, and Python 3 for the `.py` harnesses.

## Re-shooting the README GIF

`demo-record.py` drives a scripted session against a live box and writes an
asciicast; [`agg`](https://github.com/asciinema/agg) turns that into the GIF in
`docs/demo.gif`. It is scripted, not hand-recorded, so it re-shoots verbatim
when behavior changes -- a GIF showing output the tool no longer produces is
worse than none. Needs `tmux` (it drives a real terminal emulator so the
editor's cursor queries are answered honestly -- a bare pty answers with a
constant and the recording overdraws itself; the script's header has the full
reason) and `agg`.

```sh
WSMANCER_PASSWORD='...' scripts/demo-record.py dc01.corp.local svc-account corp.local
agg --cols 100 --rows 28 --font-size 16 --theme dracula --idle-time-limit 1.2 \
  demo.cast docs/demo.gif
```

The password is taken from the environment and target/account are referenced on
camera as `$TARGET`/`$USER`/`$REALM`, so nothing box-specific or secret is baked
into the published GIF.

## Two rules, if you add one

They are stated in full in `docs/verification.md`, and both were learned here the
hard way:

- **No credential reaches a tracked file**, including a unit-test fixture. Take
  them from the environment, as everything here does.
- **Prove the harness can fail before believing it passed.** Build the broken
  version, re-run, and confirm it notices, then check the mutant actually
  compiled, because a failed `go build` leaves the previous binary in place and
  the "differential" re-tests the good one.

And the trap that has cost the most time: any script driving a bare
`pty.openpty()` **must** answer the terminal's cursor query (`ESC[6n` →
`\x1b[24;1R`), on every read, forever. A read that consumes one without
answering wedges the client and presents as a transport fault.
