<div align="center">

# wsmancer

**A PSRP-native WinRM shell for offensive Windows work: typed JSON output, message sealing against locked-down listeners, and a session that survives dropped connections.**

[![CI](https://github.com/sresarehumantoo/wsmancer/actions/workflows/ci.yml/badge.svg)](https://github.com/sresarehumantoo/wsmancer/actions/workflows/ci.yml)
[![Go 1.25+](https://img.shields.io/badge/go-1.25%2B-00ADD8?logo=go&logoColor=white)](https://go.dev/dl/)
[![License: LGPL-3.0](https://img.shields.io/badge/license-LGPL--3.0-blue.svg)](LICENSE)
[![Single static binary](https://img.shields.io/badge/build-single%20static%20binary-informational)](#install)

![wsmancer in action](docs/demo.gif)

</div>

wsmancer speaks the PowerShell Remoting Protocol end to end, so command results
come back as **typed objects** rather than scraped console text, and it
authenticates against **stock, locked-down listeners**, the default
`AllowUnencrypted=false` box that refuses an unsealed request. One static Go
binary, no runtime dependencies.

## Features

- 🧾 **Structured output (`-o json`).** Real PSRP objects become typed JSON with
  every PowerShell stream intact, usable from another program or an agent, not
  only a human at a prompt.
- 🔒 **Auth that holds up against a hardened target.** NTLM and Kerberos with
  WinRM message sealing, pass-the-hash, and certificate auth. The sealing is
  **integrity-checked in both directions**, not merely encrypted. On plain 5985
  a sniffer sees ciphertext, which is why this works where a naive client gets a
  401.
- ⏩ **Tab completion that asks the target.** Local and remote **paths**, the
  box's own **cmdlet names** (cached on connect, ~1900 of them), and
  **parameters and their values** through PowerShell's own `TabExpansion2`,
  plus inline "ghost text" suggestions from your history.
- 🧷 **A session that recovers.** A dropped connection re-dials and re-attaches
  the same shell; the runspace and the in-flight command usually survive it. A
  shell the target has *forgotten* is detected and re-opened **loudly**, never
  silently.
- 🤖 **Built for automation as well as a prompt.** `-x` runs one command and
  exits with its status; `-x -` streams a whole command list over a **single
  connection** with the runspace persisting between them, one JSON object per
  result. Every built-in works in all three modes; they share one dispatch path.
- 🧰 **The full post-ex set.** Script loading (`-s` + `menu`), `services` recon,
  in-memory .NET execution (`invoke-binary`), shellcode injection
  (`donut-loader`), and `bypass-4msi`: every command upstream evil-winrm v3.9
  ships, each verified against a real target.
- 🌐 **SOCKS5 pivoting, TLS, mutual TLS.** `--proxy` for a pivot (where
  proxychains silently can't work on a static binary), `-S` with proper
  certificate verification, and client certs.

The flags are evil-winrm's, deliberately: all 20 of them, so existing muscle
memory and existing scripts carry over unchanged. The lineage, and the payloads
this owes to that project, are in [Credits](#credits-and-license).

> [!IMPORTANT]
> **Authorized use only.** This is an offensive security tool, for penetration
> testing, red teaming, CTFs and lab work. Use it only against systems you own
> or have explicit permission to test. What you do with it is your
> responsibility.

## Contents

- [Install](#install) · [Quick start](#quick-start)
- [Transport security: sealing and TLS](#transport-security-sealing-and-tls)
- [Authentication](#authentication) · [Interactive shell](#interactive-shell)
- [File transfer](#file-transfer) · [Structured output](#structured-output)
- [Loading PowerShell scripts](#loading-powershell-scripts) · [`bypass-4msi`](#bypass-4msi)
- [Session logging](#session-logging) · [Pivoting: `--proxy`](#pivoting---proxy)
- [Status](#status) · [Credits and license](#credits-and-license)

## Install

Requires Go 1.25+.

```sh
go install github.com/sresarehumantoo/wsmancer/cmd/wsmancer@latest
```

or build from a clone:

```sh
git clone https://github.com/sresarehumantoo/wsmancer
cd wsmancer
go build -o wsmancer ./cmd/wsmancer
```

Either way the result is a single static binary with no runtime dependencies.
`make check` runs what CI runs; [`CONTRIBUTING.md`](CONTRIBUTING.md) is the
developer guide.

## Quick start

```sh
# password
wsmancer -i dc01.corp.local -u svc-account -r corp.local -p 'Passw0rd!'

# pass-the-hash
wsmancer -i 10.10.10.5 -u Administrator -H <nthash>

# Kerberos from a ticket (ccache or kirbi)
wsmancer -i dc01.corp.local -K user.ccache -r CORP.LOCAL
wsmancer -i dc01.corp.local -K user.kirbi  -r CORP.LOCAL

# one-shot, JSON out
wsmancer -i 10.10.10.5 -u u -p p -o json -x 'Get-Process | select -First 3'

# through a pivot (chisel, ligolo-ng, msf socks_proxy, ssh -D)
wsmancer -i dc01.corp.local -u u -p p --proxy socks5://127.0.0.1:1080
```

Any line you type that isn't a built-in is sent to the remote PowerShell
runspace. `help` lists the built-ins; `exit` / Ctrl-D quits.

---

## Transport security: sealing and TLS

This is the part most worth understanding, because WinRM has **two independent
encryption layers** and they are easy to confuse.

```
┌───────────────────────────────────────────────────────────────┐
│ Layer 2  TLS transport   (HTTPS, port 5986, via -S)           │
│ wraps the entire HTTP connection in modern crypto             │
│ ┌───────────────────────────────────────────────────────────┐ │
│ │ Layer 1  message sealing   (NTLM / Kerberos)              │ │
│ │ encrypts the SOAP body with keys from the auth            │ │
│ │ exchange; the command and its output live here            │ │
│ └───────────────────────────────────────────────────────────┘ │
└───────────────────────────────────────────────────────────────┘
```

### Plain HTTP (5985) is not plaintext

The default WinRM listener sets `AllowUnencrypted=false`. That does **not** mean
"require TLS"; it means "require the SOAP body to be **sealed** by the
negotiated auth mechanism." So even on the plain-HTTP port 5985, wsmancer
encrypts every command body with keys derived from the NTLM/Kerberos handshake
(RC4 for NTLM, AES or RC4 for Kerberos). **A passive sniffer on 5985 sees
ciphertext, not your commands.** This message sealing is why the tool works
against stock, locked-down listeners at all, and it is the common case, because
most WinRM targets expose only 5985.

What sealing does *not* give you is strong server authentication (NTLM is
relay-able) or, for NTLM, strong crypto (RC4). That is what TLS adds.

### TLS (5986): secure by default

When you use `-S` (HTTPS, port 5986), wsmancer **verifies the target's
certificate against the system roots by default**, like any correct TLS client.
Nothing is silently trusted. You then have four choices:

| Flag | Behavior | Security |
|------|-----------|----------|
| *(none)* | verify against the system trust store | authenticates public/enterprise-CA certs |
| `--ca-cert <pem>` | additionally trust this CA | authenticates internal/self-signed certs whose CA you hold |
| `--accept-fingerprint <sha256>` | pin one exact certificate by hash | authenticates a specific cert you already know |
| `--insecure` | skip verification (encrypted, unauthenticated) | **MITM-vulnerable**; prints a warning |

Only `--insecure` is unauthenticated, and it says so loudly. Verification lives
in `internal/session/tls.go`.

### Working with a target whose cert you don't already trust

Almost every internal WinRM HTTPS listener uses a **self-signed** cert, so the
default verify will (correctly) refuse it:

```
$ wsmancer -i host -u u -p p -S -x whoami
Error: ... x509: certificate signed by unknown authority
  server cert SHA-256: b9:60:a3:99:...:4e:8a (CN=host, self-signed)
  to proceed: --accept-fingerprint b9:60:...:4e:8a to pin it,
              --ca-cert <pem> to trust its CA, or --insecure to skip verification
```

The error hands you the presented certificate's fingerprint and the exact flags,
so you don't need `openssl` to move forward. From here, in increasing order of
security:

1. **`--insecure`**, fastest. Encrypted but unauthenticated. On an internal
   engagement where you are the one positioned on the network, the active-MITM
   risk to your own traffic is usually low, so this is often the pragmatic call,
   it is also exactly what the original evil-winrm always did.

2. **`--accept-fingerprint <hash>`**, pin the cert. **Read this carefully:** a
   fingerprint you obtained over the same network path (from the error above, or
   from `openssl s_client`) proves *continuity*, not *first-contact identity*. If
   a MITM is already in the path, you would pin **their** cert. Pinning still
   buys you a lot: it detects if the cert later *changes* (box rebuilt, someone
   starts intercepting) and guarantees you keep hitting the same endpoint, but
   the trust model is SSH-on-first-connect, not real authentication. Get the hash
   out of band (below) if MITM is in scope.

3. **`--ca-cert <pem>` with an out-of-band anchor**, the only option that
   authenticates first contact, and in AD it is often achievable:
   - WinRM HTTPS certs in a domain are frequently issued by the **enterprise
     PKI (AD CS)**, not self-signed. That root is published in AD and readable by
     any domain account, `certutil -store -enterprise Root` on a domain-joined
     host, or over LDAP from the `CN=Certification Authorities,CN=Public Key
     Services,CN=Services,CN=Configuration` container. Pull it out of band and
     pass `--ca-cert enterprise-root.pem`, now a MITM cannot forge a chain to it.
   - For a self-signed target, if you can read the cert from a host you already
     control (its cert store, a config file), that is an out-of-band channel too.

### Getting a fingerprint yourself

```sh
# straight off the socket
openssl s_client -connect host:5986 </dev/null 2>/dev/null \
  | openssl x509 -noout -fingerprint -sha256

# from a PEM/DER file
openssl x509 -in cert.pem -noout -fingerprint -sha256
```

A "fingerprint" is the **SHA-256 of the certificate's DER encoding**, the same
value the tool recomputes from the cert the server presents. Note this is *not*
the Windows **thumbprint**, which is a SHA-1 hash and a different value.
`--accept-fingerprint` accepts the hash with or without colons, any case.

---

## Authentication

| Mode | Flags |
|------|-------|
| Password (NTLM) | `-u <user> -p <pass>` (or `$WSMANCER_PASSWORD`, or leave it off to be prompted), `-r <domain>` |
| Pass-the-hash (NTLM) | `-u <user> -H <nthash>` |
| Kerberos | `-K <ticket> -r <REALM>`; the ticket may be a ccache or a kirbi (detected by content, base64 accepted), `--spn` prefix (default `HTTP`), `--skew` for a target whose clock runs ahead |
| Client certificate | `-S -c <cert.pem> -k <key.pem>` with **no** `-p`/`-H`/`-K`; the target maps the certificate to an account, so no username is sent |

The first three seal the WSMan message body, so they work against
`AllowUnencrypted=false` listeners over both 5985 and 5986. Certificate auth
seals nothing, no handshake happens, so there is no session key to seal with,
and is HTTPS-only, which is what satisfies the same requirement. It also needs
the target configured for it in advance (`Service\Auth\Certificate` plus a
`WSMan:\localhost\ClientCertificate` mapping); `scripts/certauth-setup.sh` shows
the whole arrangement.

Giving `-c/-k` *together with* credentials is a different thing: the certificate
then goes into the TLS handshake alongside NTLM/Kerberos (mutual TLS), rather
than acting as the credential.

With none of `-p`, `-H` or `-K`, the password is asked for on the terminal (echo
off, prompt on stderr so `-o json` stays machine-readable). A piped or scripted
session is never prompted; it fails with the credentials error instead of
blocking on a read nobody will answer.

---

## Interactive shell

On a terminal the prompt has full line editing (elsewhere, pipes, scripts, it
falls back to plain reads so automation is unchanged):

> **On an odd terminal**, set `WSMANCER_EDITOR=plain` to skip line editing and
> read plain lines instead. The editor asks the terminal where the cursor is at
> startup and waits for the reply, so a terminal that never answers leaves you
> with a prompt that accepts nothing, which looks like a network problem but is
> not. `TERM=dumb` (or unset) selects the plain reader automatically; this is the
> escape hatch for a terminal that claims to be capable and isn't. Color is
> suppressed by `--no-colors`, by `NO_COLOR`, or by a `dumb`/unset `TERM`.

| Key | Action |
|-----|--------|
| Up/Down, Ctrl-P/N | command history (in-memory unless `-Y/--history`) |
| → / End | accept the inline autosuggestion ("ghost text") |
| Ctrl-A / Ctrl-E | start / end of line |
| Ctrl-W / Ctrl-U | delete word / line |
| Ctrl-R | search history |
| Ctrl-L | clear screen |
| Tab | complete a path |
| Ctrl-C | cancel the running command, or clear the line if idle |
| Ctrl-D | exit |

As you type, the most recent matching command from this session's history is
shown greyed-out after the cursor; press → to accept it.

**History is in memory only unless you ask otherwise.** Session commands
routinely contain passwords and hashes, so nothing is written to disk by default.
`-Y/--history` opts in to a per-target history that survives reconnects:

```
wsmancer -i forest.htb.local -u svc-alfresco -p '<password>' -Y
Info: command history: ~/.wsmancer/history/forest.htb.local.hist (on disk, prefix a command with a space to keep it out)
```

Each target gets its own file (`--history-tag NAME` to override, so several boxes
can share one or one box can keep several), mode `0600` under a `0700` directory,
and `$WSMANCER_HISTORY_DIR` moves the lot. As in any shell, **a command typed
with a leading space is not recorded**, use it for the one-off
`net user bob P@ssw0rd` you would rather not leave behind. Up-arrow, Ctrl-R and
the ghost text all read the persisted history, so reconnecting to a box picks up
where you left off.

**Tab completion is context-aware.** `upload` completes a local path then a
remote one; `download` the reverse; and every other command's path arguments,
plus a path-shaped first word like `.\bin.exe`, complete against the **target**
over PSRP. A failed or slow remote listing yields no candidates (never an error);
`-N` disables remote completion entirely.

**Commands complete too.** The first word is matched against every command the
target can run, cmdlets, functions, aliases and applications, so `invoke-w<Tab>`
gives `Invoke-WebRequest` and `Invoke-<Tab>` lists the lot. Matching ignores case,
which is how anyone actually types PowerShell:

```
PS C:\Users\svc-alfresco\Documents> stop-serv<Tab>
PS C:\Users\svc-alfresco\Documents> Stop-Service
```

The list is fetched once per session (~0.4s) and filtered locally after that, so
only the first Tab costs a round trip. `menu` re-reads it, which is what to run
after an `Import-Module` on the target.

**Parameters and their values complete too**, using PowerShell's own engine on
the target, so you get whatever that cmdlet really accepts, including live
values and enum members:

```
PS C:\> Get-Process -<Tab>          ->  -Name  -Id  -InputObject  -Module ...
PS C:\> Get-Process -Name con<Tab>  ->  conhost
PS C:\> Set-ExecutionPolicy -ExecutionPolicy Rem<Tab>  ->  RemoteSigned
```

Path arguments still complete as paths. Not every cmdlet ships an argument
completer (`Get-Service -Name` has none on Server 2016, `Get-Process -Name`
does), and a target that has locked down `TabExpansion2` simply offers nothing
here. `-N` disables all of it.

**Ctrl-C during a command** terminates the pipeline on the target (not just the
local wait), so the shell doesn't wedge behind a still-running command. It takes
about a second (measured ~0.74s median, 1.35s max against a live box).

The terminate has to share the one connection the running command is polling on,
so cancel latency is bounded by that poll, `WSMANCER_POLL_SECONDS` (default
`1`) trades responsiveness against traffic. Raising it to `5` cuts the polling to
one request every five seconds if you would rather be quieter on the wire; the
polls only happen while a command is actually running.

**A dropped connection recovers by itself, and usually the running command
survives it too.** The transport re-dials and WinRM re-attaches the same shell,
your working directory, variables, functions and anything loaded with `-s` are
all still there. The in-flight command normally completes anyway, because this
shell does not stream: PowerShell renders the result on the target and it crosses
the wire in one burst when the pipeline finishes, so a break before that has
nothing to destroy and the replay wins (measured 17/17 across break offsets from
1.2s to 8s).

The exception is a break landing *in* that final burst, which does lose the
result, and says so rather than handing you a silent empty one:

```
Error: connection to the target dropped; this command was lost.
   The session reconnects automatically, run it again.
```

**A shell the target has *forgotten* is different, and says so.** If WinRM
restarts, an administrator removes the shell, or it sits idle past the listener's
`IdleTimeout` (30 minutes by default), there is nothing left to re-attach to. The
shell opens a fresh one so the session keeps working, and tells you plainly that
the runspace went with the old one:

```
Error: the target no longer has this shell (it was restarted or timed out).
   A new shell has been opened.
   Session state was LOST: working directory, variables, functions,
   any -s scripts, and any bypass-4msi patch. Re-load what you need.
```

The warning is deliberately loud rather than a silent reconnect. `bypass-4msi`
patches AMSI inside the process serving the shell, so a new shell is unpatched,
carrying on as though it survived would send your next post-ex command straight
into AMSI. The failed command is not re-run for you, for the same reason.

**The line editor** is
[reeflective/readline](https://github.com/reeflective/readline). The `peterh/liner`
fallback that shipped for one release behind `WSMANCER_EDITOR=liner` has been
removed. `WSMANCER_EDITOR=plain` still does something, and is the escape hatch
described under *Interactive shell* above: it skips line editing entirely rather
than selecting a different editor.

## File transfer

```
upload   <local> [remote]     copy a file or directory to the target
download <remote> [local]     copy a file or directory from the target
```

Files ride inside PowerShell as chunked base64 (there is no WinRM file channel),
every transfer is SHA-256 verified, and a progress bar is drawn on a terminal.
`--chunk-size` tunes the per-round-trip size (default 192 KB; lower it if a
hardened target rejects a chunk with HTTP 413).

**Wildcards.** A source path containing `*` or `?` is expanded, locally for
`upload`, on the target for `download`:

```
upload   /tools/*.exe   C:\Windows\Temp\     # every local .exe into the remote dir
download C:\inetpub\logs\*.log   ./logs/     # every matching remote file into ./logs
```

A single match behaves exactly like naming the file (destination may be a new
name); multiple matches require the destination to be a directory. Only `*`/`?`
trigger globbing; they are illegal in Windows filenames, so a pattern is
unambiguous, while `[ ]` stay literal (a `[...]` class still works alongside
`*`/`?`). Matching is non-recursive.

## Structured output

`-o json` emits one object per command with every PowerShell stream (output,
error, warning, verbose, …) as typed JSON instead of a formatted table, the
reason wsmancer exists. `-x <cmd>` runs a single command and exits, which pairs
well with JSON for scripting.

`-x` runs the line through the **same dispatch as the interactive shell**, so
every built-in has a non-interactive form; there is no feature you can only
reach by typing at a prompt:

```sh
wsmancer -i host -u u -p p -x 'upload ./Rubeus.exe C:\Windows\Temp\r.exe'
wsmancer -i host -u u -p p -o json -x services | jq '.output[] | select(.Privileges)'
wsmancer -i host -u u -p p -x 'invoke-binary Rubeus.exe hash /password:x'
```

Two consequences worth knowing:

- **The built-ins shadow their remote namesakes**, here as interactively: `-x
  help` and `-x clear` are this tool's, not the target's. Reach the target's
  through their real cmdlet names (`-x 'Get-Help ...'`, `-x Clear-Host`).
- **The exit code is meaningful**: 0 on success, 1 if the command failed,
  including a PowerShell error record, which is a failure that produces perfectly
  normal-looking output. In `-o json` the same verdict is the `had_errors` field.

Ctrl-C during a one-shot terminates the pipeline on the target rather than
abandoning it locally, the same way it does in the shell.

### Batch mode: `-x -` (one connection, many commands)

`-x -` reads commands from **stdin**, one per line, and runs each through the
same dispatch over a **single authenticated connection**. This is the form
built for an agent or a script driving a whole session: authentication and the
runspace are paid for once, so state, the working directory, variables,
functions, `-s` scripts, in-memory assemblies, **persists across commands**,
and with `-o json` each command's result streams out as one NDJSON object as it
completes.

```sh
# One handshake; $x set on the first line is still there on the third.
printf '$x = whoami\ncd C:\\Windows\nWrite-Output "$x in $((Get-Location).Path)"\n' \
  | wsmancer -i host -u u -p p -x -

# Structured: one JSON object per line, consumed as a stream.
printf 'whoami\nhostname\nservices\n' \
  | wsmancer -i host -u u -p p -o json -x - | jq -c '{type, command, had_errors}'
```

- **Every line is self-describing.** Under `-o json` each line carries a `type`:
  `result` (a command's output/streams/verdict), `error` (a failure not tied to
  a rendered command), or `event` (a session-level notice, e.g. the target
  forgot the shell and a new one was opened, with `state_lost: true` so the
  consumer knows to re-establish what it relied on). A batch **recovers and
  continues** across a forgotten shell rather than abandoning the run.
- **A failure mid-batch does not abort it.** The lines after a failing command
  still run; the aggregate exit code is 1 if any command failed, 0 otherwise.
- **stdin is the command source, so a password cannot be prompted**, pass
  `-p`, `-H`, or `-K`.

The full envelope contract and stability guarantees are in
[`docs/json-output.md`](docs/json-output.md).

## Loading PowerShell scripts

Point `-s` at a local directory of `.ps1` files, then type a script's name to
load it into the remote runspace (base64'd and chunked in; functions defined at
top level persist for the rest of the session):

```
wsmancer -i host -u u -p p -s ~/tools/ps
PS C:\> PowerView.ps1        # load it
PS C:\> menu                 # list what you've loaded
PS C:\> Get-NetUser          # now callable, and Tab-completes
```

`menu` lists the functions you've imported (default PowerShell built-ins are
filtered out) and registers them, along with the `.ps1` names under `-s`, for
Tab-completion as first words. A path-qualified name (`.\x.ps1`, `C:\x.ps1`) is
*not* intercepted, so running a script that already lives on the target still
works.

`services` lists non-system services with their binary path and whether you can
query each, the raw material for service-based privesc (unquoted paths, weak
permissions). In `-o json` the rows come back as typed objects (`Privileges` is a
real boolean).

`invoke-binary` runs a local .NET assembly in the target's memory, no file ever
touches disk. It streams the assembly to the runspace as base64 (chunked to
respect the envelope size, like `-s`) and executes it through the CyberVaca
reflection loader, returning the assembly's captured output:

```
PS C:\> invoke-binary /opt/csharp/Rubeus.exe triage
PS C:\> invoke-binary Rubeus.exe kerberoast,/outfile:hashes.txt   # bare name from -e
```

Point at any local path, or, with `-e/--executables <dir>`, call an assembly
by bare name (it resolves in that directory, and its `.exe` files Tab-complete).
Arguments are comma-separated, matching the loader's parser; because that parser
splits on space *and* comma, an individual argument cannot contain a space.

`donut-loader` injects [donut](https://github.com/TheWover/donut) shellcode into a
process already running on the target, `OpenProcess`, `VirtualAllocEx`,
`WriteProcessMemory`, `CreateRemoteThread`, driven by upstream's embedded x64
loader. The `.bin` is a *local* file; it never touches the target's disk.

```
PS C:\> donut-loader -process_id 3312 -donutfile /opt/donut/payload.bin
PS C:\> donut-loader 3312 /opt/donut/payload.bin      # positional shorthand
```

Both flag orders work and `-donutfile` Tab-completes against your local
filesystem. **x64 targets only.** Before anything is uploaded the target is
checked for a 64-bit runspace and for the pid actually being alive, so a typo
costs one round trip instead of a full payload upload followed by silence; on
success the process being injected is named back to you. Unlike upstream, which
inlines the whole base64 into a single command, the payload is chunked like `-s`
and `invoke-binary`, so a shellcode blob of any real size doesn't overrun
`MaxEnvelopeSizekb`.

### `bypass-4msi`

Patches `AmsiScanBuffer` in the current runspace so PowerShell stops submitting
script content to AMSI. Upstream's payload is re-obfuscated on every invocation,
that is load-bearing rather than cosmetic, since AMSI scans the very script that
patches it, and it runs as ten separate commands so no single one carries the
whole patch. Expect it to take ~20s.

```
PS C:\> bypass-4msi
Info: patching AMSI in 10 steps (~18s)...
Info: AMSI patched in this runspace
```

It is the noisiest thing here and nothing else depends on it, so do it last, and
only when you need it. Every step of a working patch is silent, so any output at
all is reported as a failure rather than glossed as success, a half-applied
patch that claimed to work would be worse than none.

## Session logging

`-l/--log` writes a timestamped transcript of the session, the target and auth
mode, every command with its working directory, the (color-stripped) output,
transfers, and errors:

```
~/.wsmancer/logs/<host>/<YYYYMMDD-HHMMSS>.log     # override root with $WSMANCER_LOG_DIR
```

```
2026-07-25 09:36:06  === session start: forest.htb.local (NTLM password + sealing) ===
2026-07-25 09:36:06  PS C:\Users\svc-alfresco\Documents> whoami
htb\svc-alfresco
2026-07-25 09:36:48  [upload] loot.txt -> C:\Temp\loot.txt (15 B)
2026-07-25 09:36:48  === session end ===
```

It works for both the interactive shell and one-shot `-x`. A logging failure is a
warning, not fatal, a shell you asked for won't be abandoned because the log
directory isn't writable.

---

## Status

**Working:** password / pass-the-hash / Kerberos auth with sealing, interactive
REPL, upload/download, text and JSON output, one-shot `-x`, TLS verification
(`--ca-cert` / `--accept-fingerprint` / `--insecure`), client certificates
(`-c`/`-k`, mutual TLS), custom `-a/--user-agent` (defaults to
`Microsoft WinRM Client`), session logging (`-l`), and SOCKS5 pivoting
(`--proxy`).

**Line editing and completion:** emacs-style editing with inline autosuggestion;
Tab completes local and remote paths, the target's command names, and its
parameters and their values (through PowerShell's own `TabExpansion2`). History
is in memory unless `-Y/--history` opts into a per-target file that survives
reconnects.

**Post-exploitation, all of upstream evil-winrm v3.9's commands are ported**, and
each was verified against a real target rather than by trusting a success
message: PowerShell script loading (`-s` + `menu`), `services` (privesc recon),
in-memory .NET execution (`invoke-binary`, with `-e/--executables`; live-tested
with Rubeus), shellcode injection into a remote x64 process (`donut-loader`;
the payload executed in the target process, which survived), and `bypass-4msi`
(the AMSI test sample is refused before the patch and runs after it, against a
box with real-time monitoring actually enabled).

**Certificate authentication** is supported: `-S -c cert.pem -k key.pem` with no
other credential authenticates by certificate alone, verified against a listener
configured for it (`scripts/certauth-setup.sh` does the target side, and tears it
down again). Giving `-c/-k` *with* a password or ticket instead presents the
certificate in the TLS handshake alongside NTLM/Kerberos, mutual TLS, which
evil-winrm cannot express.

## Pivoting: `--proxy`

To reach a listener that is only routable from inside the target network, point
`--proxy` at a SOCKS5 proxy:

```sh
wsmancer -i dc01.corp.local -u svc -p 'pw' --proxy socks5://127.0.0.1:1080
```

`socks5h://` is accepted as a synonym, `user:pass@` is supported, and
`$WSMANCER_PROXY` sets it for a whole engagement (the flag wins over it).
Every auth mode works through it, password, pass-the-hash, Kerberos and
certificate, over both HTTP/5985 and HTTPS/5986.

**Do not reach for proxychains here; it cannot work.** proxychains hooks
`connect(2)` by `LD_PRELOAD`-ing a shim over libc, and this tool is a static Go
binary that issues syscalls directly and never calls libc's `connect` at all.
The shim is simply never invoked, so the dial goes out of your own interface.
It does not fail; it *silently ignores the proxy*. That is the whole reason this
flag exists.

The target's name is resolved **at the proxy**, never locally, what other tools
spell `socks5h`. An internal FQDN with no answer on your resolver therefore
works, which also means Kerberos gets the real hostname for its SPN.

The banner tells you the route was taken:

```
Info: connecting to http://dc01.corp.local:5985/wsman via socks5 127.0.0.1:1080
```

Everything else is unchanged: NTLM/Kerberos sealing, TLS on `-S` (verified
against the *target's* name, not the proxy's), certificate auth, Ctrl-C and file
transfer all behave the same proxied.

## Full flag reference

Run `wsmancer --help`.

## Credits and license

wsmancer began as a Go port of
[Hackplayers/evil-winrm](https://github.com/Hackplayers/evil-winrm) (LGPL-3.0)
and owes that project its command surface: every one of its flags and every
post-exploitation command it ships is implemented here, which is why the two are
interchangeable at the command line. Three PowerShell payloads are used verbatim
from it and carry their authors' work: `invoke-binary.ps1` and
`donut-loader.ps1` by Luis Vacas (CyberVaca), and the AMSI patch behind
`bypass-4msi` (re-obfuscated per invocation here, but the technique and the
payload are upstream's). They live in `internal/shell/assets/`.

wsmancer is therefore **LGPL-3.0** as well, see `LICENSE`. The
`--accept-fingerprint` cert-pinning model follows
[ligolo-ng](https://github.com/nicocha30/ligolo-ng).

PSRP itself comes from [smnsjas/go-psrp](https://github.com/smnsjas/go-psrp)
(MIT, © Jason Simons), which builds on
[smnsjas/go-psrpcore](https://github.com/smnsjas/go-psrpcore). wsmancer depends on
[sresarehumantoo/go-psrp](https://github.com/sresarehumantoo/go-psrp), a fork of
it (still MIT) carrying the transport changes this tool needs and upstream lacks:
a pluggable authenticator so the NTLM/Kerberos sealing layer can be dropped in,
pipeline termination for Ctrl-C, an adaptive Receive timeout, and WS-Addressing
`RelatesTo` correlation. Each patch is marked `Fork patch` in that repo's source
and the reasoning is in `docs/architecture.md`.
