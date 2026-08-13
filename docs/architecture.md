# Architecture notes

The per-package rationale behind the layout map in `CONTRIBUTING.md`, why each
piece is shaped the way it is, and which parts are load-bearing.
`CONTRIBUTING.md` keeps a one-or-two-line entry per package and points here;
read the relevant section before changing a package. The fork's patches are at
the bottom.

## `cmd/`

`cmd/wsmancer/` is the CLI entry point. `cmd/sealcheck` is not part of the
product binary, but it is not throwaway either: it is the driver
`scripts/verify-matrix.sh` runs to prove the auth+sealing layer (each matrix row
is a `wsmancer-sealcheck` invocation), and CI builds it as a link-check for the
obscure go-psrp/go-psrpcore dependency, so it stays buildable. (`cmd/probe`, a one-shot
diagnostic that dumped PSRP's concrete Go types while `internal/output` was being
written, was genuinely throwaway and has been removed.)

## `internal/shell/`, the REPL and post-ex

The interactive REPL: prompt, built-in dispatch, file transfer, Ctrl-C handling,
and the Tab handler that wires `complete` + `lineedit` to the session.

`postex.go` holds `-s` script loading (base64+chunk a `.ps1` into the runspace
via `Invoke-Expression`) and `menu` (diff the runspace functions against a
baseline, minus known built-ins, and register the rest for completion).
`invokebinary.go` holds `invoke-binary` (the embedded `assets/invoke-binary.ps1`
wrapper + `-e` exe resolution/completion) and `donutloader.go` holds
`donut-loader` (the embedded `assets/donut-loader.ps1` wrapper +
`-process_id`/`-donutfile` parsing, and a `preflight` probe, the wrapper's own
x64 guard can only fire *after* the whole payload is uploaded, and it is silent
on a pid that isn't running, so both are checked in one round trip first).

All three share `sendvar.go`'s `sendB64Var` to stream a payload into a global in
envelope-sized chunks. That chunking is a deliberate divergence for donut:
upstream inlines the entire base64 into one command, which overruns
`MaxEnvelopeSizekb` for any real payload. `sendB64Var` also watches `sigs` (see
Conventions in `CONTRIBUTING.md`) and length-checks the assembled variable
before the caller runs it, a dropped chunk is otherwise invisible for donut,
which would inject truncated shellcode just the same.

### `bypass4msi.go`

Upstream's payload is embedded as a *template* and re-obfuscated per invocation,
and that randomisation is **functional, not decoration**: AMSI scans the script
that patches AMSI, so a payload carrying the literal `amsi.dll` /
`AmsiScanBuffer` is flagged before it can run. `obfuscateBypass` reproduces
upstream's four transformations (function names, variable names,
`<><marked<><` literals into character arithmetic, then keyword casing), and the
payload is run as ten separate commands split on `#jump` so no single command
carries the whole patch.

- **One deliberate divergence, and upstream is broken without it.** Upstream
  invokes `GetProcAddress` with the `IntPtr` that `GetModuleHandle` returned,
  but on Server 2016 the only overload takes a `HandleRef`, so upstream's
  Bypass-4MSI dies at step 3 with "Object of type 'System.IntPtr' cannot be
  converted to type ... HandleRef" and never patches anything. Verified live,
  both ways. The template now inspects the chosen overload and wraps the handle
  only when needed, so both shapes work.
- Every step of a working patch is silent, so *any* output or error record is
  treated as failure. Claiming success after a half-applied patch would be the
  worst possible lie here, since the operator's next move assumes AMSI is gone.
- Ctrl-C is honoured between steps (~18s of deliberate pauses), the same lesson
  `sendB64Var` learned.

## `internal/lineedit/`

Line editor behind an `Editor` interface. On a terminal it wraps
`reeflective/readline` (emacs-style editing, arrow history, zsh-style inline
autosuggestion, colored prompt); plain reads for pipes/scripts. History is
in-memory *by default* (session commands contain secrets), reeflective saves
accepted lines to whichever source is registered, so the shell records nothing
itself and the default source keeps it in memory. `-Y/--history` opts into
`internal/history` (below), which is the one way anything reaches disk.

The load-bearing parts of this package are the source-verified Ctrl-C invariant
(the editor must hold raw mode only per-read, or it swallows the SIGINT the shell
needs) and the completion adapter; touch it carefully.

Ctrl-E accepts the ghost text as well as moving to end of line (zsh does the
same). It has to be a *macro* bind expanding to End-then-Right, not a rebind:
only reeflective's `forward-char` accepts a suggestion, `end-of-line` merely
moves, and `autosuggest-accept` alone does nothing when no suggestion is
pending, which would silently cost us end-of-line in the common case. The
trailing Right is a no-op with nothing to accept, so plain end-of-line survives;
`pty-test.py` asserts both halves.

## `internal/complete/`

Context-aware Tab completion. `upload` = local→remote, `download` = remote→local,
`invoke-binary`'s exe arg = local/`-e` (resolved in the shell, which owns `-e`),
every other command's path args (and a path-shaped first word like `.\bin.exe`)
complete against the target. `donut-loader` is the one flag-driven site:
`TargetOptions` offers its parameter names (carried in `Context.Options`), and
whether a word is the local `.bin` is decided by the preceding flag rather than
by position.

The **first word** also completes against the target's own commands,
`internal/shell/verbs.go` fetches every name `Get-Command` reports (~1900 on a
stock box, one ~0.4s round trip) and caches it for the session, so filtering is
local afterwards. Three deliberate edges: the fetch is skipped on an empty word
(a bare Tab should show the handful of built-ins, not a wall of cmdlets), a
failed fetch backs off for 30s rather than latching for the session or re-paying
the 5s timeout every keystroke, and `-N` suppresses these candidates outright,
its promise is "disables remote completion entirely", not just remote *paths*.

A **parameter or a parameter's value** (`-Na`, `-Name con`) instead goes to
`TargetPSNative`, which defers to the target's own `TabExpansion2`
(`internal/shell/psnative.go`), that is where parameter names, argument values
and enum members come from, and completing them against a directory listing
yielded nothing at all before. Three things make it fit the existing contract:
PowerShell's **`ReplacementIndex` is the authority** on where the word starts
(its parser understands `-Param`, `$var.`, quoting), so that site returns its
own head instead of the tokenizer's `WordStart`, splicing at a different
offset corrupts the line; `unquotePS` normalises PowerShell's already-quoted
`CompletionText` back to a raw value so it flows through the same
`Quote`/`requoteAfter` pipeline as everything else, rather than being quoted
twice; and the cursor/index cross the wire as **character** counts while the
shell splices by **byte** offset (`byteOffsetForRune`). Paths deliberately stay
on `TargetRemote`, that path is proven and its quoting is tuned to the editor.
A target with no `TabExpansion2` (ConstrainedLanguage, JEA) backs off for 30s
rather than paying the timeout on every Tab.

The cache is dropped by `menu`, the operator's explicit "re-read what this
session can run". Note `builtinFunctions` must **not** filter this list: that
map exists to keep `menu` honest about what the operator loaded, whereas
completion positively wants `Get-FileHash`, `mkdir` and friends.

## `internal/output/`

Renders results in `text` (remote Out-String, printed verbatim) or `json`
(PSObjects normalized to typed JSON). `RenderText` also prints the
**Information** stream: PowerShell 5.1 files `Write-Host` there, not on the
output stream, so skipping it silently swallowed the only thing many post-ex
scripts ever say (including the donut wrapper's x64 refusal). `InformationText`
unwraps the InformationRecord's `MessageData`, rendering the record whole dumps
Source/TimeGenerated/Computer in map order.

## `internal/transfer/`

Upload/download over PSRP. No WinRM file channel, so bytes ride inside
PowerShell as base64, chunked, SHA-256 verified. Local paths built from
attacker-controlled remote filenames are constrained to the destination dir
(`safeLocalPath`), the Ruby version had a traversal bug here. `*`/`?` in a
source path glob (locally via `filepath.Glob`, remotely via `Get-Item -Path`);
single match ⇒ name-it semantics, multi ⇒ dest is a dir.

## `internal/history/`

Opt-in (`-Y/--history`) on-disk command history, one file per connection tag
(default: the target) under `~/.wsmancer/history/`
(`$WSMANCER_HISTORY_DIR` overrides), 0600 in a 0700 dir, nil-safe like
`transcript`. Two things are load-bearing and easy to break:

- The **leading-space opt-out** (`Recordable`) lives in `Write`, not in the
  shell. The *library* decides when a line is accepted and writes it to the
  registered source, so the shell never sees the moment a line is recorded,
  and it trims the line before anything else, which would destroy the
  leading-space signal even if it did.
- `rl.History.Add` **replaces** reeflective's default in-memory source while it
  is the only one, which is what makes Up-arrow, Ctrl-R and the ghost text all
  read the persisted lines, i.e. what makes history survive a reconnect.

Turning this on reverses a posture the tool deliberately shipped with, which is
why it is opt-in and loud about what it writes to disk.

## `internal/proxydial/`

`--proxy`: SOCKS5 pivoting, so a listener reachable only from inside the target
network can be driven from outside. It exists as code because the usual answer
cannot work here: **proxychains hooks `connect(2)` via an `LD_PRELOAD` libc
shim, and a static Go binary issues syscalls directly**, the shim is never
called, so the dial silently goes out of the attacker's own interface rather
than erroring.

Only SOCKS5 is accepted (chisel, ligolo-ng, msf `socks_proxy`, `ssh -D`); an
HTTP CONNECT proxy solves the opposite problem, egress rather than ingress.
Names always resolve **at the proxy** (`socks5h` semantics, and the only useful
behavior, an internal FQDN has no local answer, and Kerberos needs the real
hostname for its SPN), so `socks5://` and `socks5h://` are synonyms here. A nil
`*Dialer` is valid and dials directly, which is what lets all four provider call
sites hold one unconditionally. `DialTLS` replaces `tls.DialWithDialer`, which
cannot be pointed at a proxy; it reproduces that function's ServerName defaulting
deliberately, left empty, the handshake fails outright, and the name that must
go out is the *target's*, not the proxy's.

## `internal/transcript/`

`-l/--log` session transcript to `~/.wsmancer/logs/<host>/`
(`$WSMANCER_LOG_DIR` overrides). Nil-safe methods so callers log
unconditionally; used by both the shell and one-shot.

## `internal/auth/ntlmseal/`

NTLMv2 with pass-the-hash + WinRM message sealing. `sealed()` decrypts sealed
responses regardless of HTTP status (a WSMan SOAP fault comes back as a sealed
HTTP 500), so the real fault surfaces instead of ciphertext, and, since NTLM's
`serverSeal` is a stateful RC4 keystream, decrypting every sealed server message
(not just 200s) keeps it in lockstep (`isSealedResponse` gates it to
actually-sealed bodies).

## `internal/auth/certauth/`

WinRM **client-certificate authentication**: the certificate in the TLS
handshake *is* the credential, no user/password/ticket. The odd one out among
the providers, it carries no crypto of its own, because no handshake happens
and so no session key exists to seal with; HTTPS is what satisfies
`AllowUnencrypted=false`. On the wire it is one fixed header on every request,
`Authorization: http://schemas.dmtf.org/wbem/wsman/1/wsman/secprofile/https/mutual`
(MS-WSMV; the same one the Ruby winrm gem's `ClientCertAuthSSL` sends). Two
things were learned against a live listener and are load-bearing:

- **TLS renegotiation must be enabled.** Windows does not ask for the client
  certificate in the initial handshake, it completes anonymously, sees a
  request for an endpoint requiring cert auth, and *renegotiates* to demand
  one. Go's default is `RenegotiateNever`, so the connection dies with `local
  error: tls: no renegotiation`, an error that names TLS and says nothing about
  certificates. Renegotiation exists only in TLS ≤1.2 (1.3 replaced it with
  post-handshake auth, which Go's client does not implement), so this path caps
  `MaxVersion` at 1.2. That cap applies to cert auth only.
- **One connection is a choice, not a requirement.** The sealing providers own
  a socket because NTLM/Kerberos authenticate a *connection*; a certificate is
  presented on every connection, so any of them is the same client. Measured: a
  build with pooling on passes the whole harness, Ctrl-C included. It is pinned
  to one anyway for predictability and to avoid a fresh handshake +
  renegotiation per connection, and if Ctrl-C latency here ever matters,
  letting a second connection exist is the thing to try.

Who you end up as is the *target's* decision (its
`WSMan:\localhost\ClientCertificate` mapping), so no username is sent and none is
printed.

## `internal/auth/krbseal/`

Kerberos AP-REQ with caller-controlled authenticator timestamp (clock-skew
tolerance without touching the system clock) + RFC 4121 §4.2.4 CONFIDENTIALITY
wrap tokens with Windows RRC rotation. Same sealed-fault decrypt as ntlmseal
(observability only here, krb wrap tokens are self-describing per message, so
skipping one never desyncs).

The two etypes divide the work differently, and it decides where the risk sits.
**AES** delegates to go-krb5's cryptosystem, so the payload's confidentiality
and integrity are upstream's problem and are vector-tested there; this package
contributes only the token framing, header layout, RRC, rotation direction and
the key-usage split (`GSSAPI_ACCEPTOR_SEAL` vs `..._INITIATOR_SEAL`). **RC4**
(etype 23, live-supported) delegates nothing: RFC 4757 §7.3's `Ksign`, `Kseq`,
`Kcrypt` and `SGN_CKSUM` are hand-rolled here out of HMAC-MD5, MD5 and raw RC4.

That asymmetry is why `vectors_test.go` exists and why it is weighted the way it
is. The whole RC4 derivation chain is *shared* between `wrapRC4` and
`unwrapRC4`, so a wrong algorithm stays self-consistent and every round-trip
test still closes, measured, not asserted: 10 of `krbseal-mutants.sh`'s 14
mutants are caught by the vectors alone. Anything touching those derivations
should expect the vectors, not the round-trips, to be what fails.
`docs/verification.md` has the differential and the caveat that the ground truth
is impacket's output rather than a published vector.

`ticket.go` reads `-K`: an MIT **ccache** or a **kirbi** (raw KRB-CRED, what
Rubeus/Mimikatz write), decided by the first byte, with base64 accepted because
that is how Rubeus prints one. Upstream converts a kirbi by shelling out to
impacket's `ticketConverter.py` and writing a `.ccache` beside the input;
nothing here wants a file in ccache shape, a KRB-CRED already carries the
ticket, the session key and the client principal, which is the whole of what
the provider reads, so it is parsed in memory, no external tool and no file
written into the operator's directory. A tool-written kirbi has an
*unencrypted* `EncKrbCredPart` (the file is the secret); one captured off the
wire does not, and that is refused by name rather than as an ASN.1 error. The
"no service ticket" message lists what the file does hold, a TGT-only ccache
and an SPN spelled for the wrong host are the two usual causes and are
invisible otherwise.

## The go-psrp fork

`go.mod` has `replace github.com/smnsjas/go-psrp => ./go-psrp-fork`. The vendored
fork carries patches upstream lacks; grep `Fork patch` to find them:

- `client.Config.CustomAuthenticator`, lets `ntlmseal`/`krbseal` drop in as the
  `auth.Authenticator`, so the sealing layer is used verbatim.
- `Client.StopPipelines`, terminates the running command(s) so Ctrl-C actually
  stops remote work (with `MaxRunspaces=1` a still-running pipeline blocks every
  later command). The details are load-bearing and were hard-won; touch this path carefully. In
  short: the terminate `Signal` must go over the
  *same* connection that owns the shell (WinRM locks a shell to its client; a
  separate connection is rejected "connected to a different client"), it signals
  the pool's locally-tracked CommandIds directly (the WSMan CommandId is the
  pipeline ID uppercased, no `Enumerate` round-trip), and it tolerates a command
  that already completed (fault `2150858843`, `isCommandGone`).
- `runPipelineReceive` completes the pipeline (`pl.Fail(ctx.Err())`) when the
  command ctx is canceled. An out-of-band WSMan terminate yields no clean PSRP
  completion, so without this `Execute`'s `pipeline.Wait()` (no ctx) hangs forever
  after Ctrl-C kills the command.
- `wsman` Receive `OperationTimeout` adapts to the caller's deadline
  (`operationTimeout`) and defaults to 1s (`defaultReceivePoll`, overridable with
  `WSMANCER_POLL_SECONDS`). The sealing transport sets the socket read deadline
  to the request context deadline; if a long-poll's server-side hold were `>=`
  that, the read would time out before the server replies, the transport would
  treat it as a dead connection and re-dial a *fresh* WSMan session, which
  orphans stateful PSRP and cascades into faults. Capping the poll under the
  deadline keeps the connection alive. The default *also* sets Ctrl-C latency:
  the terminate waits out the in-flight poll, so cancel time is
  `uniform(0, cap) + RTT`. Measured: 1s gives ~0.74s median / 1.35s max at
  a cost of 1 Receive/s *while a command runs* (an idle shell polls not at all).
- `transport.describeBody` never dumps an HTTP error body raw. A non-text one is
  summarized by size, on a sealed connection an error body is encrypted
  ciphertext, and dumping it scrambled the terminal, and a WSMan SOAP fault is
  reduced to one line by `soapFaultSummary` (`transport/soapfault.go`). WinRM
  answers a refused request with a fault *at HTTP 500*, so the body never reaches
  `wsman.ParseFault` (which only runs on a success); it read as "mostly text" and
  went to the terminal envelope and all, ~1.8 KB of namespaced XML per fault. The
  parsing is duplicated rather than reused because `wsman` imports `transport`.
  Two things are load-bearing: the numeric `Code` and the WSManFault message text
  are carried through verbatim, because callers match on both (`isCommandGone`
  recognizes an already-finished command by code `2150858843`, the reconnect path
  by "shell was not found"); and the fields are read as *all* descendant text,
  since a provider fault nests the real message inside a second `WSManFault`.
  The generic `Reason` is dropped whenever there is a message, it only restates
  the subcode that is already printed.
- `checkRelatesTo`, called from `sendEnvelope`, correlates every response to the
  request that produced it, comparing the WS-Addressing `MessageID` the client
  stamped on the request against the `RelatesTo` the server echoes back. All 11
  request methods funnel through `sendEnvelope`, so no path opts out. This is the
  stack's **only** replay/substitution defence: the sealing layers give integrity
  but not freshness, and Kerberos in particular has no freshness signal available
  at its own layer (the acceptor's sequence number is a measured constant zero on
  both etypes, so `ntlmseal`'s counter check cannot be copied over, the
  measurement is in `docs/verification.md`). Correlation therefore lives here, a
  layer up, and covers both auth mechanisms at once.
  - A **missing** `RelatesTo` fails the request. Absence must not be a skip, or
    stripping one header is the bypass.
  - The compare is **case-insensitive**, and that is not cosmetic: the fork
    generates the ID inconsistently, `Delete` uses `uuid.New().String()` while
    every other call site wraps it in `strings.ToUpper`, and servers echo back
    the case they were given. A case-sensitive compare would have that one call
    site reject its own server's reply. No live harness reaches it, so
    `TestRelatesToIsCaseInsensitive` is the only guard.
