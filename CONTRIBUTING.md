# Contributing / working on wsmancer

`README.md` is the user-facing doc (usage, flags, the transport-security
walkthrough). This file is for working *on* the code: what lives where, how to
build and test it, and the conventions that bind across packages. Keep the two
in sync when behavior changes.

This file is the **index**. The detail lives in `docs/`:

| Doc | What's in it |
| --- | --- |
| `docs/architecture.md` | Per-package rationale behind the layout map below, and the go-psrp fork's patches. Read the relevant section before changing a package. |
| `docs/verification.md` | The live-target harness catalog: what each script proves, its traps, its differential. Read before running or writing a harness. |
| `docs/upstream-parity.md` | Parity with upstream evil-winrm v3.9, the deliberate divergences, the post-ex build order, closed gaps. |
| `docs/json-output.md` | The `-o json` contract: the NDJSON stream, the `type` discriminator, the envelope fields, object normalization, and the stability guarantee. Read before changing anything a consumer parses. |

## Layout

Each entry is the one-line version; `docs/architecture.md` has the rationale and
the load-bearing details for every package below.

- `cmd/wsmancer/`, the CLI entry point. `cmd/sealcheck` builds
  `wsmancer-sealcheck`, the driver `scripts/verify-matrix.sh` runs and CI
  link-checks, not throwaway.
- `internal/cli/`, flag parsing; evil-winrm-compatible flags (`-i -u -p -H -r
  -K -S -N -o` …).
- `internal/session/`, wraps a go-psrp client: turns CLI options into an
  authenticated PSRP runspace and runs commands (`RunFormatted` for text,
  `RunRaw` for json, `StopPipelines` for Ctrl-C). `tls.go` builds the HTTPS
  verification config. `Renew` swaps in a freshly built client when the target
  has forgotten the shell; `build` is split out of `New` so both paths select the
  auth provider by identical rules.
- `internal/shell/`, the interactive REPL: prompt, built-in dispatch, file
  transfer, Ctrl-C handling, and the Tab handler wiring `complete` + `lineedit`
  to the session. `oneshot.go` is the `-x` entry (`NewOnce`/`Once`): it runs one
  line through the *same* `dispatch`, with no editor and no history, and returns
  the exit code, so every built-in has a non-interactive form (see the
  convention below). `batch.go` (`NewBatch`/`Batch`) is the `-x -` entry: it reads
  commands from stdin and runs each through that same `dispatch` over one
  connection, so the runspace persists between them; unlike a one-shot it keeps
  `once` false, so a forgotten shell is recovered onto and the run continues.
  `forgotten.go` recognizes a shell the target no longer has and recovers onto a
  new one, announcing the state loss (see the convention below). `postex.go`
  (`-s`, `menu`), `invokebinary.go`, `donutloader.go` (+ its `preflight` probe)
  and `bypass4msi.go` are the post-ex set; all payload streaming goes through
  `sendvar.go`'s `sendB64Var`, which chunks into envelope-sized pieces, honours
  Ctrl-C, and length-checks the result. `bypass4msi.go`'s per-invocation
  obfuscation is **functional, not decoration**, AMSI scans the script that
  patches AMSI.
- `internal/lineedit/`, line editor behind an `Editor` interface; wraps
  `reeflective/readline` on a terminal, plain reads for pipes/scripts. History is
  in-memory by default (session commands contain secrets). **Preserve the
  Ctrl-C raw-mode invariant when touching this package**: reeflective enters raw
  mode per read (`MakeRaw` on entry, restore on return), so while a remote
  command runs the terminal is in cooked mode and Ctrl-C reaches the shell's
  SIGINT handler; an editor that held raw mode for its whole lifetime would
  swallow it. Verified in reeflective's source, re-verify after a dependency bump.
  - **Being a character device is not enough to get the terminal editor**
    (`preferPlain`). reeflective asks the terminal for the cursor position
    (`ESC[6n`) and waits for the answer on `os.Stdin` with **no timeout**,
    guarded only by "is stdin a tty", so a tty that never answers blocks at
    startup, after the prompt is printed, looking exactly like a dead transport.
    `TERM` empty or `dumb` therefore takes the plain reader, and
    `WSMANCER_EDITOR=plain` forces it for the terminal that claims to be
    capable and is not. That last one cannot be a heuristic: discovering the
    answer requires sending the query, by which point it is too late.
    `dumbterm_test.go` is the gate and needs no target, so **it runs in CI**,
    one of the three such harnesses, alongside the two mutation gates. It carries
    a control (`TestSilentTTYSanity`) that asserts the *unguarded* path still
    hangs; if that ever starts passing the guard has stopped being load-bearing.
    The first draft of it passed against unguarded code because the prompt is
    written before the query is sent, so the assertion is the returned *line*.
- `internal/complete/`, context-aware Tab completion: local vs remote paths per
  command, the target's command names (cached `Get-Command`, ~1900 names) for the
  first word, and the target's own `TabExpansion2` for parameters and their
  values. `-N` disables all of it.
- `internal/output/`, renders results as `text` (remote Out-String, verbatim) or
  `json` (PSObjects normalized to typed JSON). Also prints the **Information**
  stream, PowerShell 5.1 files `Write-Host` there, and skipping it swallowed the
  only thing many post-ex scripts ever say.
- `internal/transfer/`, upload/download over PSRP: base64 inside PowerShell,
  chunked, SHA-256 verified, globbing on both sides. Local paths from
  attacker-controlled remote filenames are constrained to the destination dir
  (`safeLocalPath`), the Ruby version had a traversal bug here.
- `internal/history/`, opt-in (`-Y/--history`) on-disk history under
  `~/.wsmancer/history/`, 0600 in a 0700 dir. The leading-space opt-out and the
  `rl.History.Add` source replacement are load-bearing.
- `internal/proxydial/`, `--proxy`: SOCKS5 pivoting. It exists because
  proxychains' `LD_PRELOAD` shim cannot hook a static Go binary's direct
  syscalls, so the dial would silently go out the wrong interface. Names always
  resolve at the proxy; a nil `*Dialer` means direct.
- `internal/transcript/`, `-l/--log` session transcript to
  `~/.wsmancer/logs/<host>/`. Nil-safe so callers log unconditionally.
- `internal/auth/ntlmseal/`, NTLMv2 + pass-the-hash + WinRM message sealing.
  Sealed responses are decrypted regardless of HTTP status, which both surfaces
  faults and keeps the stateful RC4 keystream in lockstep. They are also
  **integrity-checked**: `unwrap` recomputes the MAC and compares the sequence
  number, per MS-NLMP 3.4.2's "if they differ, the message MUST be discarded".
  Sealing alone gives confidentiality but not integrity, RC4 is malleable and
  length-preserving, so without the check an in-path attacker on 5985 could XOR
  chosen deltas into a response and the shell would render the result as the
  target's own words. A failure is terminal for the connection (the keystream
  cannot be rewound), so it closes and re-handshakes rather than retrying.
- `internal/auth/certauth/`, client-certificate auth; the certificate *is* the
  credential. Needs TLS renegotiation enabled (hence `MaxVersion` 1.2 on this
  path only), and the target's mapping decides who you become.
- `internal/auth/krbseal/`, Kerberos AP-REQ with caller-controlled authenticator
  timestamp (skew without touching the clock) + RFC 4121 wrap tokens with Windows
  RRC rotation. `ticket.go` reads `-K` as ccache, kirbi, or base64 kirbi.
  Responses are **integrity-verified**, for the same reason as `ntlmseal` above
  and by the same rule, both wrap formats are length-preserving, so an unwrap
  that only decrypts lets an in-path attacker on 5985 choose what the operator
  reads. The two etypes need different work, and the difference is easy to get
  wrong: **AES** gets payload integrity free from the etype's own HMAC inside
  `crypto.DecryptMessage`, but that does not cover the 16-byte token header,
  which travels in the clear, RFC 4121 §4.2.6.2's echoed copy inside the
  ciphertext is what binds it, and comparing the two is ours to do. **RC4**
  (etype 23, a live-supported auth mode, `verify-matrix.sh` has a row for it)
  gets nothing free: `unwrapRC4` must recompute RFC 4757 §7.3's SGN_CKSUM, and
  must check the direction tag, because RFC 4757 keys both directions
  identically and so the client's own request reflected back would otherwise
  verify. A verification failure fails the request and drops the connection
  rather than passing the body on, unwrapping is not a diagnostic.
  The *algorithms* are also pinned offline, by `vectors_test.go`: wrap tokens
  produced by impacket, an independent implementation, frozen as bytes. That
  closed a real hole, every other test here builds its input with the production
  `wrap`, so a self-consistent wrong RFC 4757 (swapped HMAC nesting, a dropped
  `xorF0`, `le32(13)` become `le32(15)`) round-tripped perfectly and was visible
  only to a live Windows DC. `krbseal-mutants.sh` measures exactly that: **10 of
  its 14 mutants are caught by nothing else.**
  This is integrity, **not** replay protection, and `ntlmseal`'s sequence check
  cannot be copied over: the acceptor's sequence number is measured to be
  constant zero on both etypes, so an `expected++` check would refuse the second
  response of every session. The freshness signal that *does* exist is
  WS-Addressing `RelatesTo`, and it is checked a layer up, in the fork's
  `sendEnvelope` (below), so the answer to "why has `krbseal` no counter" is
  not "add one" but "correlation lives in `wsman`". `docs/verification.md` has
  the measurement and the case-sensitivity trap.

## The go-psrp fork

`go.mod` has `replace github.com/smnsjas/go-psrp => ./go-psrp-fork`. The vendored
fork carries patches upstream lacks; grep `Fork patch` to find them, and see
`docs/architecture.md` for why each one is shaped the way it is:

- `client.Config.CustomAuthenticator`, lets `ntlmseal`/`krbseal` drop in as the
  `auth.Authenticator`, so the sealing layer is used verbatim.
- `Client.StopPipelines`, terminates the running command(s) so Ctrl-C actually
  stops remote work. Hard-won; the Ctrl-C conventions below capture the
  constraints (it shares the one connection the running command polls on).
- `runPipelineReceive` fails the pipeline on ctx cancellation, or `Execute`'s
  ctx-less `pipeline.Wait()` hangs forever after Ctrl-C.
- `wsman` Receive `OperationTimeout` adapts to the caller's deadline and defaults
  to 1s (`WSMANCER_POLL_SECONDS`). It must stay *under* the socket read
  deadline or the transport re-dials a fresh WSMan session and orphans stateful
  PSRP; it also sets Ctrl-C latency.
- `transport.describeBody` never dumps an HTTP error body raw, sealed bodies are
  ciphertext that scrambles the terminal, and a SOAP fault is reduced to one line
  by `soapFaultSummary`. Callers match on both the numeric code and the message
  text, so both are carried verbatim.
- `checkRelatesTo` in `sendEnvelope` correlates every response to the request
  that produced it (WS-Addressing `MessageID` → `RelatesTo`), and is the stack's
  **only** replay/substitution defence, the sealing layers give integrity but
  Kerberos has no freshness signal available (see `internal/auth/krbseal`). A
  missing `RelatesTo` fails; absence must not be a skip, or stripping one header
  is the bypass. The compare is case-insensitive because `Delete` builds its
  `MessageID` lowercase while every other call site upper-cases it, a latent
  trap no live harness can reach, so `TestRelatesToIsCaseInsensitive` is not
  redundant.

## Build / test / run

```sh
make check                           # what CI runs: gofmt + go vet + both test sets
make build                           # -> ./wsmancer
make mutants                         # the ntlmseal + krbseal mutation gates (no target needed)

./wsmancer -i dc01.corp.local -u svc-account -r corp.local -p "$PASS"
```

**Prefer `make check` to a bare `go test ./...`.** The fork is a *separate
module*, so `./...` from the root silently skips it, including the `wsman`
tests covering `checkRelatesTo` and the SOAP-fault summariser. `make test` runs
`./internal/...` and then `cd go-psrp-fork && go test ./wsman/...`, which is what
CI does; running only the former means a local pass proves less than a CI pass.
Never `go test ./...` *inside* the fork either: its go.mod replaces
`../go-psrpcore` with a directory that does not exist here, so only the patched
packages are testable.

The `wsmancer` binary is gitignored.

## Verifying against a live target

Auth/sealing and the interactive shell can only be fully proven against a real
WinRM box, and the harnesses assume a locked-down listener
(`AllowUnencrypted=false`, HTTP/5985), a permissive box makes every "pass"
meaningless. **`docs/verification.md` is the full catalog** and owns the
detail: ground rules, per-script traps, differentials, per-harness command lines,
and the setup for `certauth`, `donut-loader` and HTTPS/5986. Read it before
running or writing a harness. Two rules bind everywhere and are stated there in
full:

- **Credentials, tickets and per-spawn state live in `lab/`**, gitignored whole,
  and nothing from it may reach a tracked file, *including unit-test fixtures*,
  the easy place to forget. History was rewritten once to redact lab credentials.
  Every harness takes its credentials from the environment for this reason; none
  has a default that would work against anyone's box but your own.
- **Prove the harness can fail before believing it passed.** The recurring
  failure mode here is not broken code; it is a test that passes for the wrong
  reason, and every harness has done it at least once. Build the broken version,
  re-run, confirm the harness *notices*, and check the mutant actually compiled,
  since a failed `go build` leaves the previous binary and re-tests the good one.

The harnesses, one line each (detail, traps and results in
`docs/verification.md`):

| Script | Proves |
| --- | --- |
| `verify-matrix.sh <host> <dc-ip>` | the auth+sealing matrix, with unsealed-refused controls first |
| `get-tickets.sh <dc-ip>` | mints the Kerberos tickets the matrix needs (impacket + faketime) |
| `pty-test.py` | terminal-only paths: line editing, ghost text, arrow history, Tab, Ctrl-C/L/D |
| `break-proxy.py` + `connection-break-test.py` | connection breaks: `idle`, `running`, `state`, `blackhole`. `running` asserts the command **survives** (this shell never streams output; it arrives in one burst at completion, so an earlier break has nothing to destroy); its re-dial check is what stops a kill that hit nothing from passing |
| `shell-forgotten-test.py` | a shell the target has *forgotten*: recovery, and that the state loss is announced |
| `oneshot-test.py` | that `-x` runs the built-ins, plus its exit codes, json and transcript |
| `batch-test.py` | that `-x -` runs a command stream over one connection with state persisting, NDJSON per command, isolated mid-batch failures |
| `ctrlc-latency.py` | Ctrl-C cancel latency, "prompt back" vs "shell usable" |
| `bypass4msi-test.py` | the AMSI patch, three ways (bytes, behavior, end-to-end) |
| `pscomplete-test.py` | parameter/value completion, and that the line is still correct after |
| `history-test.py` | the opt-in persistent history, across a reconnect |
| `proxy-test.py` (`--offline`, `--netns`, live) | `--proxy`, asserting on what the proxy *saw* |
| `password-prompt-test.py` | the interactive password prompt (ECHO bit, stderr, restore) |
| `upload-cancel-test.py` | Ctrl-C during the payload-streaming phase |
| `transfer-edge-test.py` | transfer edge cases against the target's own `Get-FileHash` |
| `certauth-setup.sh` + `certauth-test.py` | client-certificate auth, with two must-fail controls |

`scripts/README.md` documents how to point them at your own box: every harness
takes its target, account and credentials from the environment.

Three harnesses need **no target** and so run in CI: the two mutation gates
(`make mutants`) and `internal/lineedit/dumbterm_test.go` (an ordinary `go
test`), a pty that never answers the editor's cursor query.

Both mutation gates exist for one structural reason, and it is **not** general
hygiene, do not spread them to other packages. `ntlmseal` and `krbseal` are the
only packages carrying crypto they implement themselves, so they are the only
ones where a *wrong* algorithm can stay self-consistent across both ends of a
session and never surface as a visible failure. Each has two test styles of
different power, and only a differential shows which is carrying which mutant:
structural tests recompute with the production code's own primitives and so
cannot see a self-consistent wrong algorithm, while `vectors_test.go` compares
against ground truth from outside the package.

- `ntlmseal-mutants.sh` breaks `internal/auth/ntlmseal` twenty ways; five are
  caught only by `vectors_test.go`, which checks MS-NLMP's **published** values.
  The NTLMv2 blob assembly lives in pure helpers
  (`ntlmv2Temp`/`ntlmv2Response`/`keyExchangeKey`) so the vectors can drive it
  directly; that is why they are split out, and why the auth path needs no test
  seams.
- `krbseal-mutants.sh` breaks `internal/auth/krbseal` fourteen ways; **ten** are
  caught only by its `vectors_test.go`. The ratio is that lopsided because the
  RC4 path's whole derivation chain is shared between `wrapRC4` and `unwrapRC4`,
  so breaking it breaks both ends identically and every round-trip test still
  closes. Its ground truth is weaker in kind, the RFCs publish no wrap-token
  vectors, so the numbers are impacket's output, regenerated by
  `scripts/krbseal-vectors.py` (needs impacket; not run by CI or `make check`,
  the frozen bytes are the artifact).

**Those counts are measured, never copied forward** (ntlmseal's has been wrong
twice); the vectors-only mutants are tagged `[vectors-only]` per mutant in each
script, and the method is in its header. Re-measure by moving `vectors_test.go`
aside and re-running.

Testing also **leaks server-side shells** until the PT30M IdleTimeout;
`docs/verification.md` has the cleanup.

**Harness trap that applies to every new script:** anything driving a bare
`pty.openpty()` must answer the terminal's DSR query (`ESC[6n` → `\x1b[24;1R`),
and answering it "in the read loop" is *not* sufficient. The query is re-issued
on every prompt redraw, mid-command included, so any read that consumes one and
returns without answering wedges the client in `GetCursorPos` for good. It then
stops draining its socket, which presents as a transport or proxy fault and cost
most of a day and three wrong explanations. Two rules generalise: **a harness
read that discards is never safe**, and when a PTY harness produces an
inexplicable transport symptom, suspect a swallowed DSR before the transport.
`docs/verification.md`'s "Cross-cutting harness traps" has the isolation table
that settled it.

## Conventions

- **`-x` is dispatch, not a second code path.** One-shot mode runs its line
  through the shell's own `dispatch`, so a built-in behaves identically to the
  interactive shell and there is no feature reachable only at a prompt. The cost
  is that built-ins shadow their remote namesakes in `-x` too (`-x help` is this
  tool's; `-x 'Get-Help ...'` is the target's), one rule for what a word means,
  in both modes. Two things `Once` carries that the REPL loop does not: the exit
  code (via `sh.failed`, because `executeAs` renders a `HadErrors` result and
  returns nil, the failure has no error value), and *not* recovering a forgotten
  shell (`!sh.once`), since there is no next command to protect. The one trap:
  `main.go` must hand `Once` a fresh `context.Background()`, because
  `signal.NotifyContext`'s `stop()` cancels the ctx it returned, passing that on
  aborts the command before it runs, and the symptom (empty output, exit 1) looks
  exactly like a rejected command. `scripts/oneshot-test.py` is the live gate.
  - **`-x -` is the same dispatch again, streamed.** Batch mode (`Batch`) reads
    stdin line by line and runs each through the identical `dispatch` over one
    connection, so the runspace (cwd, variables, functions, `-s` scripts,
    in-memory assemblies) persists between commands; this is the property that
    beats a sequence of separate `-x` processes, and the whole reason batch mode
    exists. It is a *session*, so unlike `Once` it keeps `once` false: a forgotten
    shell is recovered onto and the run continues (emitting a `type:"event"`
    `shell_recovered` record so a consumer re-establishes lost state), rather than
    being abandoned. The exit code is the aggregate, 1 if any command failed. One
    constraint falls out of stdin being the command source: a password cannot be
    prompted there, so `-x -` with no `-p/-H/-K` is a usage error rather than a
    hang. `scripts/batch-test.py` is the live gate, with a per-line control that
    keeps the state-persistence claim from passing vacuously.
- Ctrl-C never kills the session: idle → clears the line; running command →
  `StopPipelines` terminates just that command and the shell returns to the
  prompt (~0.74s median, 1.35s max; measured live). This spans the shell, the fork's
  `StopPipelines`/`runPipelineReceive`, and the seal layer. The shell also
  sanitizes any error before printing it (`sanitizeTerminal`), so binary/control
  bytes in an error can never scramble the terminal, and skips rendering a
  canceled command's (aborted) result.
  - The payload-streaming phase honours Ctrl-C too: `sendB64Var` takes `sigs` and
    checks it *after* each chunk, so a `-s` script, an `invoke-binary` assembly or
    a `donut-loader` blob stops uploading and nothing is ever run. Checking after
    rather than before the chunk is the load-bearing part: a Ctrl-C arriving
    during the *final* chunk must still be consumed here, or it stays buffered
    (cap 1, nothing drains it between commands) for the next `executeAs` to pick
    up, which then terminates a command the operator never meant to stop. That
    was the original bug; `sendvar_test.go` pins the loop and
    `scripts/upload-cancel-test.py` pins the end-to-end behavior against a live
    box.
  - It deliberately does **not** cancel the in-flight chunk's context. A chunk is
    one small string append, so waiting costs a single round trip (less than a
    ~0.74s `StopPipelines`) and leaves no abandoned pipeline for the one-runspace
    pool to queue the caller's cleanup behind. Decisively: a mid-`Execute` cancel
    is *undetectable* in this loop; the fork returns `(result, nil)` with
    "context canceled" as a plain string in `Result.Errors`, so an `err != nil`
    check sees success and, on the last chunk, yields a silently truncated
    payload. The post-stream length check is the backstop for that class of
    failure however it arises.
- Tab completion must never disturb the prompt, a failed or slow remote listing
  yields no candidates (5s timeout), never an error. A failed fetch backs off for
  30s rather than latching or re-paying the timeout every keystroke. `-N`
  disables remote completion entirely, command names as well as paths.
- The prompt is colored, and whether color happens at all is `output.Colors`'
  decision alone, the editor has no say. It used to: liner miscounted ANSI
  escapes as columns and rejected control runes, so it forced a plain prompt
  through an `Editor.SupportsColorPrompt()` seam. Both are gone with liner; an
  editor that can't render escapes would have to bring that seam back.
  `output.EnvDisablesColor` folds the environment into the `--no-colors` flag:
  `NO_COLOR` present at any value (the no-color.org convention is presence, so
  `NO_COLOR=0` still disables), or `TERM` empty/`dumb`. It shares that `TERM`
  test with `lineedit.preferPlain` deliberately, a dumb terminal should get a
  plain prompt *and* plain output, not one of each.
- **TLS is secure by default.** Two independent layers: message *sealing*
  (NTLM/Kerberos) encrypts command payloads even on plain HTTP/5985, that's the
  whole point of `internal/auth/*`, so 5985 is not plaintext, and *transport*
  TLS on 5986 (`-S`). The 5986 path verifies against the system roots by default;
  `--ca-cert` adds a private anchor, `--accept-fingerprint` pins a cert by SHA-256
  (following ligolo-ng, secure, stateless, MITM-safe on first connect), and
  `--insecure` opts out (the only path that prints a warning).
  - All verification runs in a **`VerifyConnection`** callback with
    `InsecureSkipVerify=true` (see `tls.go` `pinVerifier`/`chainVerifier`). Not
    `VerifyPeerCertificate`: the built-in chain check aborts *before* any
    callback on failure, so it can't show the cert. `VerifyConnection` always
    runs with `cs.PeerCertificates` in hand, which is how a failed verify names
    the peer's SHA-256 + a copy-pasteable `--accept-fingerprint` hint. SNI still
    goes out (`ServerName` is set); `InsecureSkipVerify` only disables the
    *built-in* check so our callback is authoritative.
  - The `*tls.Config` is handed to the auth providers whole; when set it is
    authoritative (`tlsExplicit`), so they don't override it back to insecure.
    Nothing touches TLS when `-S` is off, no config, no warning.
- **The auth providers own the request path.** `ntlmseal`/`krbseal`'s
  `connRoundTripper` writes the raw HTTP requests and builds the TLS handshake
  itself (go-psrp's transport is bypassed). So request-level and TLS-level knobs
  live there, not in go-psrp: the `User-Agent` (`-a`, defaults to
  `Microsoft WinRM Client`, the old `*-spike` value was an IOC) is set in
  `write()`, and the client certificate (`-c/-k`) goes into the `tls.Config`
  `tls.go` builds. Anything header- or TLS-shaped is wireable here without
  touching the fork.
  - **They own the dial, too**, which is why `--proxy` is a field on each
    provider's `Config` rather than anything in go-psrp. Three of the four sites
    are the sealing providers' `dialAndHandshake`/`dialAndAuth`; the fourth is
    `certauth`, which drives an `http.Transport` and so takes the dialer as its
    `DialContext`. Those four are the whole of this tool's egress, Kerberos
    reads its ticket from a file and never contacts a KDC, so proxying them
    proxies everything. A nil dialer means direct, so no site branches on it.
- **The socket deadline is never zero** (`writeDeadline`/`deadCommsBackstop`, in
  both providers). A command's context is cancel-only, so without a backstop a
  *silently blackholed* connection, dropped VPN, NAT timeout, leaves the
  response read blocked forever, and Ctrl-C can't rescue it because
  `StopPipelines` wants the same connection mutex. The backstop must stay well
  above the longest legitimate server hold (`PT60S`, plus the Receive poll) or it
  recreates the connection churn an earlier fix removed, the tests assert that
  relationship, not the literal 120s. A connection break otherwise *recovers*:
  the re-dial re-attaches to the same shell and the runspace (variables,
  functions, cwd, `-s` scripts) survives.
- **A forgotten shell is not a connection break, and must not share its path.**
  When the target no longer has the shell at all (WinRM restart, the PT30M
  IdleTimeout, an admin removing it) there is nothing to re-attach to, so
  `internal/shell/forgotten.go` detects it and `session.Renew` opens a *new*
  client, the fork's `Close` latches `closed`, and a client whose shell is gone
  still reports itself connected, so reconnecting the old one cannot work.
  Recovery is **loud and never re-runs the command**: the new runspace has none
  of the old one's state, and `bypass-4msi` patches AMSI in the process the shell
  ran in, so a silent re-create would leave the operator's next post-ex command
  walking into an unpatched AMSI. Detection keys on the fault's *message text*,
  never on WSManFault code `2150858843`, that code also means "command
  identifier that does not exist", which `StopPipelines` provokes routinely, so
  keying on it would let an ordinary Ctrl-C destroy a live runspace.
