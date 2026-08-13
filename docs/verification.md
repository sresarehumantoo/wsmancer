# Verifying against a live target

The full harness catalog: what each script proves, the traps it had to learn,
and the differential (deliberately broken build) that showed it can fail.
`CONTRIBUTING.md` carries the short index and the two rules that apply
everywhere; this file is the detail behind it. Keep both accurate when a harness
changes.

## Ground rules

**Credentials, tickets and per-spawn state live in `lab/`**, which `.gitignore`
excludes whole. It is not part of this repo and never will be: it is where
`scripts/get-tickets.sh` writes the tickets, the measured clock skew and the
rendered krb5 configs, and where `scripts/verify-matrix.sh` reads them from. A
`lab/README.md` of your own, the box's credentials, how to re-derive skew and
tickets after a respawn, the command line for each harness, and the cleanup each
one owes the box, is worth keeping there; it is the difference between starting
a live session in a minute and rediscovering all of it. Nothing from that
directory may reach a tracked file: this repo's history was rewritten once
already to redact lab credentials, which changed every commit SHA before
2026-07-27.

That rule reaches **unit-test fixtures**, which is the easy place to forget it,
a hardcoded password in a `_test.go` is as committed as one in an argument list,
and a test needs only *a* password, never the lab's. Neutral values
(`testuser` / `example.local` / `testpass`) are what belong there; the lab's had
to be swapped out of `internal/auth/ntlmseal`'s tests once, caught by a scan
during a push rather than by review. Note the asymmetry when scanning: a
*hostname* or *account name* is not by itself the signal, but no harness here
carries one either, since target, account and credentials all come from the
environment (`scripts/README.md` lists them). Passwords, NT hashes and AES keys
are the signal, and none of those belong in a tracked file at all.

**Prove the harness can fail before believing it passed.** The recurring failure
mode in this repo is not broken code, it is a test that passes for the wrong
reason, and every harness here has done it at least once: an assertion matching
the terminal's *echo* of what was typed rather than the command's output; one
matching the editor's inline history suggestion; a prefix that is a substring of
its own completion (`Get-Service -Na` inside `Get-Service -Name`), so the "tail"
reads the same either way; a probe whose text contains both of its own possible
answers; a test case aimed at a cmdlet with no argument completer, so there was
nothing to complete; an end-to-end check that cannot fail on a target where
nothing is enforcing; and a hardcoded `True`. So: build the broken version,
re-run, and confirm the harness *notices*, the per-script notes below record
what each differential showed. Check the mutated binary actually compiled, too;
a failed `go build` leaves the previous binary in place and the "differential"
then re-tests the good one.

Auth/sealing and the interactive shell can only be fully proven against a real
WinRM box, and the test scripts assume a locked-down listener
(`AllowUnencrypted=false`, HTTP/5985), a permissive box makes every "pass"
meaningless.

## The harnesses

Target, account and credentials come from the environment for every one of them;
`scripts/README.md` is the table of what to set to point them at your own box.

That parameterisation was itself live-gated on Forest (2026-08-11), because a
harness that no longer names its target can fail open, an assertion built from
an empty variable matches anything, and a ccache path that is silently ignored
proves nothing. Re-run after the change: `get-tickets.sh` minted both tickets at
the right enctypes (RC4 23 / AES256 18) through its new `TARGET`/`ADMINUSER`
interface with the krb5 configs rendered per run, `verify-matrix.sh` **6/6** with
both controls denying, `pty-test.py` **23/23**, `certauth-setup.sh` +
`certauth-test.py` **16/16** (and the teardown left only `Transport=HTTP`),
`password-prompt-test.py` **12/12**, `oneshot-test.py` **16/16**,
`batch-test.py` **16/16**. Two differentials say the new variables are
load-bearing rather than decorative: a bogus `MXCCACHE`/`MXADMIN` fails exactly
the RC4 and pass-the-hash rows and leaves the AES row (which reads
`MXCCACHE_AES`) passing, and a wrong `WSM_WHOAMI` fails exactly the three
`pty-test.py` checks that assert on identity, 20/23, not 23/23, so the derived
regex is not matching vacuously.

- `scripts/verify-matrix.sh <host> <dc-ip>`, the auth+sealing matrix. Runs two
  controls first (unsealed traffic must be refused) so a pass means something.
- `scripts/get-tickets.sh <dc-ip>`, mints the Kerberos tickets the matrix needs
  (uses impacket + faketime for the lab DC's clock skew). For the **kirbi** side
  of `-K`, convert one of those with impacket's `ticketConverter.py <in>.ccache
  <out>.kirbi`, a real tool-written kirbi, which is the only fixture that proves
  the unencrypted-`EncKrbCredPart` assumption holds in practice. Verified on
  Forest: the kirbi, the same kirbi base64-encoded, and the original ccache all
  authenticate; the pre-change build fails on that kirbi with `load ccache:
  Invalid credential cache data. First byte does not equal 5` while still
  accepting the ccache, which is the differential.
- `scripts/pty-test.py <host> <user> <realm> <password>`, drives the shell
  through a real PTY to exercise the terminal-only paths (line editing, ghost
  text, arrow history, Tab completion, Ctrl-C/L/D) that piped stdin never hits.
  It sets no editor env var, and scrubs an inherited one, so it always tests what
  ships. Assertions are semantic, edit a line, check which command actually ran,
  rather than scraped from redraw escapes, and where the point is that a command
  *ran*, the token is built on the target (`'D-' + 'TWO'`) so the terminal's echo
  of what was typed cannot satisfy it. Two exceptions look at escapes because
  they must: the colored prompt, and Ctrl-L, which asserts the whole-screen
  erase (`CSI 2 J`) specifically, since every ordinary keystroke repaint ends in
  `CSI 0 J` and accepting that made the check pass on a build with no editor at
  all. Differential: against a build whose `New` never returns the terminal
  editor, 14 of the 23 checks fail (every completion, arrow-history and Ctrl-L
  one); the survivors are the genuinely editor-independent Ctrl-C/Ctrl-D ones.
- `scripts/break-proxy.py <listen> <host> <port> <killfile>` +
  `scripts/connection-break-test.py <scenario> …`, break the TCP connection at
  an exact moment (no root, no waiting on an idle timeout) and see what survives.
  Scenarios: `idle`, `running`, `state` (does the runspace survive a re-dial),
  and `blackhole` (a *silently* discarded flow, the case that proved the
  unbounded-read hang; the proxy's blackhole mode is sticky, restart it between
  runs). How the connection dies is the whole point: an RST recovers, a blackhole
  used to hang forever.
- `scripts/shell-forgotten-test.py <host> <user> <realm> <password> [trace]`,
  the *other* way a session dies: the target no longer has the shell at all
  (WinRM restarted, an administrator removed it, the PT30M IdleTimeout elapsed).
  Distinct from every `connection-break` scenario, and the distinction is the
  point, a broken connection re-attaches to the same shell and the runspace
  survives, a forgotten shell cannot be re-attached and the state is gone. It
  proves both halves: the session **recovers** (a new shell, usable prompt) and
  the operator is **told the state was lost**. The second is the one that
  matters, because `bypass-4msi` patches AMSI in the process the shell ran in, so
  a new shell is unpatched and an operator who believed otherwise would run their
  next post-ex command into AMSI.
  - **How it forgets the shell**, which is what makes it cheap to run: not a
    WinRM restart (svc-alfresco cannot restart services, and it would disrupt
    every other harness) and no waiting out the idle timeout. The session under
    test reports the PID of the `wsmprovhost.exe` serving it (`$PID`); a *second*
    connection enumerates the listener's shells, `Get-WSManInstance -ResourceURI
    shell -Enumerate` reports each one's `ProcessId`, and removes exactly that
    one. Unprivileged, since a user may remove their own shells, and it leaves
    the box otherwise untouched. Unlike most harnesses here it **leaks no
    server-side shell**: verified `SHELLCOUNT=1` afterwards, that one being the
    checking connection's own.
  - **Traps it is built against.** The two controls run *before* the removal, so
    "the state is gone" cannot pass by never having been planted. The state probe
    is the **same command** before and after, a true differential rather than
    two probes that could differ for unrelated reasons, and it reads the planted
    function through `Get-Command … -ErrorAction SilentlyContinue` rather than
    calling it: an undefined function throws `CommandNotFoundException` and takes
    the whole expression's output with it, which cost a run before it was fixed.
    That probe is also a *paired* assertion, the same command emits a `STATE=`
    prefix, because an absence check ("the variable is empty") passes for free
    against a dead shell that ran nothing at all. Every marker is assembled on
    the target (`'SENT' + 'INEL7F3A'`) so the terminal's echo of the typed line
    cannot satisfy the match.
  - Verified **12/12** on Forest. The differential is decisive: against a build
    whose `shellForgotten` returns false, which *is* the pre-fix behavior, it
    scores **2/12**, passing only the two controls that run before the removal.
    That run is also what corrected the old "incidental evidence says it degrades
    cleanly" note: the fault was readable and the session was dead, with every
    later command failing identically and the prompt still displaying the working
    directory of a shell that no longer existed. Detection keys on the fault's
    message text, never on fault code `2150858843` (which also means "command id
    does not exist", which `StopPipelines` provokes routinely).
- `scripts/oneshot-test.py <host> <user> <realm> <password>`, that `-x` runs the
  shell's own dispatch, so every built-in has a non-interactive form. Before the
  change `-x` wrote its line straight to the runspace, so `-x services` ran a
  cmdlet that does not exist and upload/download/menu/help had no one-shot form at
  all. What only a live target can show, and a unit test cannot (it has no box, so
  every one of these paths is stubbed or absent there): a built-in *runs over the
  wire* (`services` returns the target's table; the old binary returns a
  cmdlet-not-found record), upload/download round-trip against the target's own
  `Get-FileHash`, plain PowerShell is unchanged (the built-ins shadow their remote
  namesakes exactly as they do interactively, `Get-Help`/`Clear-Host` reach the
  box), and `-o json`/`-l` carry through the one-shot path. It also pins the exit
  code in **both** directions: a failing remote command exits 1 even when it
  produced normal-looking output, which is the half a naive port drops because
  `executeAs` renders a `HadErrors` result and returns nil, only `sh.failed`
  separates it from success.
  - **The trap it was written to catch, and did.** `main.go`'s ctx comes from
    `signal.NotifyContext`, whose `stop()` *cancels* it; the first draft passed
    that ctx to `Once` after calling `stop()`, so the command was canceled before
    it ran. The symptom, empty output, exit 1, is indistinguishable from a
    target that rejected the command, and every unit test passed (they use a fresh
    `context.Background()`). Only the live run surfaced it. Fixed by handing `Once`
    a fresh background context, matching what the interactive path already did.
  - **Differential.** Point `WSM_BIN` at a build from before the change (`git
    stash && go build -o /tmp/wsm-old ./cmd/wsmancer && git stash pop`) and
    exactly the six built-in rows fail while every plain-PowerShell, exit-code,
    json and transcript row passes, which is what makes those six the
    discriminator rather than "the old binary is worse across the board".
    Measured on Forest 2026-08-01: **16/16** on this build, **10/16** on that one.
    The `services` row needs Administrator (svc-alfresco cannot open the SCM);
    pass its NT hash as `WSM_ADMIN_HASH` or that one row degrades to a permission
    error rather than the intended cmdlet-not-found differential.
- `scripts/batch-test.py <host> <user> <realm> <password>`, that `-x -` runs a
  stream of commands over **one connection** with the runspace persisting between
  them, which is the property no sequence of separate `-x` calls can have and the
  whole reason batch mode exists. What only a live target can show: a `$var`, a
  `cd` and a defined function set on early lines are visible on a later one; the
  `-o json` stream is exactly one typed object per command with no banner or
  prompt leaking onto stdout; a `{"id":…,"command":…}` request echoes its id on
  the response (string and numeric) while a bare line mixed in carries none; a
  failure mid-batch does not abort the run (the
  later lines still execute and emit, only the failing one carries `had_errors`,
  aggregate exit is 1); an all-succeeding batch exits 0.
  - **The differential is built into the harness.** The persistence rows would
    pass vacuously if the target just happened to remember a variable, so a
    CONTROL issues the same three probes as *separate* `-x` processes and asserts
    they do **not** share state, a passing persistence row is then the single
    connection, not a target-side accident. If a refactor ever broke the
    single-runspace guarantee (a per-command reconnect), the persistence rows
    would read the same empty state the control does and fail while the control
    still passes. There is also a coarse differential against any pre-feature
    binary: it has no `-x -`, so `-` is sent to PowerShell as a literal command
    and the batch-capability rows fail. Measured on Forest 2026-08-01: **16/16**
    on this build, **4/16** on the pre-feature binary (the 4 that hold are the
    control, the lone error object still being valid JSON, no prose on stdout,
    and the literal `-` command coincidentally exiting 1).
  - The forgotten-shell recovery *event* (`{"type":"event",
    "event":"shell_recovered"}`) is not exercised here, provoking it means
    killing the shell mid-batch, which `shell-forgotten-test.py` does for the
    shared recovery path, but its json rendering is unit-tested in
    `internal/output`.
- `scripts/ctrlc-latency.py <host> <user> <realm> <password> [samples]`, times
  Ctrl-C-cancels-a-running-command, reporting both "prompt back" and "shell
  usable" (the latter is what the operator feels). Latency is
  `uniform(0, poll cap) + RTT`, so it takes several samples to mean anything; set
  `WSMANCER_POLL_SECONDS` to re-measure the latency/traffic trade-off.
  It creates and verifies a whitespace-bearing path on the target (then cleans it
  up), answers the editor's cursor-position query, and delivers the
  during-command Ctrl-C as a real SIGINT (the PTY controlling-terminal dance is
  orthogonal to the shell's handler).
- `scripts/bypass4msi-test.py <host> <user> <realm> <password|nthash>`, proves
  the AMSI patch three ways, and which ones *apply* depends on the target:
  - **bytes**, the 12 bytes at `AmsiScanBuffer` became the stub.
  - **behavior**, `AmsiScanBuffer`'s HRESULT became the stub's hardcoded
    `0x80070057`, where the real code returns S_OK or a provider status such as
    `0x80070015` (ERROR_NOT_READY).
  - **end-to-end**, a sample AMSI blocks before the patch runs freely after.
    This is the only real proof, and it is **unassertable where nothing is
    enforcing**: the sample runs before *and* after, so the check cannot fail.
    Forest's default is exactly that, Defender running with current signatures
    and its AMSI provider registered, but `DisableRealtimeMonitoring=1`. The
    harness detects this and prints a SKIP with the reason rather than passing
    quietly.
  Two things learned the hard way here. **When AMSI is enforcing, the harness's
  own probes get blocked**, they contain `amsi.dll` / `AmsiScanBuffer` and read
  as the very bypass they measure, so the probes are defined twice, once up
  front and once after the patch, and the "before" readings are best-effort.
  And the registry route to enabling monitoring does not work: Defender protects
  its own key (`Requested registry access is not allowed`) and `WinDefend` cannot
  be stopped even as admin. Use the supported API, as admin:
  `Set-MpPreference -DisableRealtimeMonitoring $false`, then **reconnect**,
  AMSI state is read at process start, so the same session shows nothing.
  Verified both ways on Forest: 8/8 enforcing (including "the obfuscated payload
  itself got past the active AMSI"), 7/7 not enforcing. Reverting the HandleRef
  fix fails it. Restore the box afterwards with `-DisableRealtimeMonitoring $true`.
- `scripts/pscomplete-test.py <host> <user> <realm> <password>`, parameter and
  value completion. The risk it exists for is not "are there candidates" but "is
  the line still correct afterwards", so the assertions **run** the completed
  command and check a token the target computed. Three traps it had to learn:
  - Do not split the buffer on the typed prefix. `Get-Service -Na` is a substring
    of `Get-Service -Name`, so the tail reads `me` whether or not anything was
    inserted, that made both the insertion check and the `-N` check hold
    unconditionally. Compare the current input line (`curline`) instead.
  - Ghost text renders a previous command inline, so a bare "is this string on
    screen" check can pass with nothing completed. Prefer a token the target
    computed.
  - `Get-Service -Name` has **no** argument completer on Server 2016
    (TabExpansion2 returns 0 matches) while `Get-Process -Name` does; asserting
    against the former tests nothing. And `-Na` is a valid abbreviation of
    `-Name`, so "the command ran" alone does not prove the completion happened.
- `scripts/history-test.py <host> <user> <realm> <password>`, the opt-in
  persistent history, which only a real session can prove: under the default
  editor the *library* decides when a line is accepted and writes it to whichever
  source is registered, so "does reeflective read and write our store" is a
  question about reeflective, and a mock would only test itself. Covers the
  round-trip across a reconnect (Up-arrow reaching the previous session), the
  leading-space opt-out, 0600, and that `-Y` off writes nothing at all. Same
  probe trap as the others: the skipped command's token is concatenated on the
  target (`'SECRET-' + 'RAN'`) so that matching it proves *output*, not the
  terminal's echo of what was typed.
- `scripts/proxy-test.py [--offline | <host> <user> <realm> <password>]`,
  `--proxy`. It runs its own SOCKS5 proxy in-process and asserts on **what the
  proxy saw**, never on the command merely working: the bug being guarded
  against is a dial that quietly goes out of the wrong interface, which against a
  target reachable both ways looks exactly like success. `--offline` needs no box
  at all, the target name used is a `.invalid` one that resolves nowhere, so a
  build that dialled directly cannot pass, and covers the CONNECT, the
  unresolved (socks5h) name, proxy credentials both ways, `$WSMANCER_PROXY`,
  and a bad URL refused at startup. `--netns` (root, offline) adds the *routing*
  proof `--offline` cannot give, see the bullet below. The live half adds a real authenticated,
  sealed session plus the control that makes it mean something: with the proxy
  *refusing*, the same session must fail. Optional flags extend it to the dial
  sites an NTLM-password run never reaches, `--hash`, `--ticket` (krbseal owns
  its own dial), and `--tls-fingerprint`/`--cert`/`--key` for the HTTPS/5986
  paths, which are **the only way `proxydial.DialTLS` is exercised at all**;
  pinning by fingerprint through the tunnel is itself the proof that
  verification ran against the *target's* certificate rather than the proxy's.
  Verified on Forest: the NTLM-only base run is **23/23** (offline 9 + core live 5
  + the nine tunnel-path checks below), and with every option supplied the full
  matrix is **33/33** (all four dial sites, both transports, all four auth modes),
  27/27 without the TLS half. Two checks are deliberately weak and
  say so in the script, the banner is a claim rather than evidence, and the
  wrong-password one is vacuous alone (a build ignoring `--proxy` also reaches no
  CONNECT), so it counts only next to its positive. Differentials: against a
  binary whose dialer always goes direct, 4 of the 9 offline checks fail, and so
  do 2 of the 5 core live ones, including the refusing-proxy control, which
  *succeeded*, i.e. the exact silent bypass this feature exists to prevent.
  One check had to be rewritten after it failed for the wrong reason: it ran
  `Get-Service`, which svc-alfresco lacks the privileges for, and counted output
  *lines*, a threshold the two banner lines nearly met on their own. It now
  round-trips 200 KB and counts the payload.
  - **`sudo proxy-test.py --netns` closes the routing gap.** The offline checks
    were always structurally sound on *DNS*, the target name is a `.invalid` one
    that resolves nowhere, so a build that resolved locally physically cannot
    pass, but the live checks were weaker on *routing*: Forest was directly
    reachable from the attacker host, so "it worked through the proxy" was also
    consistent with the proxy being ignored, and only the refusing-proxy control
    ruled that out (evidence someone remembered to write, not a property of the
    setup). `--netns` makes the direct route impossible rather than merely
    unused: it runs the client in a network namespace whose only route out is the
    proxy (a `/30` veth to the host, no default route), so a direct dial gets
    `network is unreachable`, the proxy records no CONNECT, and **no control is
    needed**, the wrong answer is physically forbidden. It needs no target: a
    dummy interface on the host (`10.200.0.1`), local to the proxy but off-net to
    the namespace, stands in for the WinRM box; pass a real target IP to point it
    at a live box instead. It needs root for `ip netns`, so it is opt-in, run
    the whole script under sudo. Setup and teardown are the script's job
    (`netns_setup`/`netns_teardown`, idempotent so a crashed run cleans up). Two
    checks: the no-proxy control (namespace can't reach the target) and the
    positive (with `--proxy`, the dial reaches it, and can only have gone through
    the proxy, since the control proved there is no other path). Verified 3/3, and
    the differential is decisive: the mutant whose dialer ignores `--proxy` fails
    the positive check with `saw [] rc=1`, it dialled direct, hit the unreachable
    wall, and reached no proxy, which is the exact silent bypass. A real
    chisel/ligolo pivot would be more realistic but buys nothing beyond this: the
    isolation is the same and the namespace is reproducible.
  - **The three tunnel-only paths are now covered** (`tunnel_path_checks`, driven
    through a PTY like the other terminal harnesses), each still asserting the
    proxy carried the session, the paths where a real tunnel differs from a
    one-shot `-x`:
    - `upload`/`download`, the most round trips of anything here. A 300 KB
      payload spans many base64 transfer chunks; its SHA-256 is verified on the
      *target* (remote `Get-FileHash`) and again on the round-tripped copy, so a
      byte-splicing bug in the tunnel would show where a one-line answer never
      could.
    - Ctrl-C, `StopPipelines` reaches the shell over the same proxied
      connection; the ~0.74s holds through the tunnel (measured 0.4-0.7s live).
      A correctness check, not the latency benchmark `ctrlc-latency.py` runs.
    - an idle session, the Receive long-poll cycles across the tunnel while
      nothing is typed (default 35s, `WSMANCER_PROXY_IDLE`). Honest limit: a
      loopback proxy has no idle timeout to trip, so this proves the session and
      its polling survive an idle gap through the proxy, not the interaction with
      a tunnel that *drops* idle flows, that is the blackhole case
      `connection-break-test.py` covers and `deadCommsBackstop` exists for.
    Differential: against the direct-dial mutant these six behavioural checks all
    still pass (Forest is reachable both ways), but the three "carried by the
    proxy" assertions fail `saw []`, which is exactly why the routing checks are
    separate from the behavioural ones. Runs whenever a live target is given; adds
    no new required flags. Each session leaks one server-side shell until the
    PT30M timeout, like every PTY harness here.
- `scripts/password-prompt-test.py <host> <user> <realm> <password>`, the
  interactive password prompt, all of which is terminal behavior: it asserts the
  **ECHO bit is clear** on the pty while the password is read (the mechanism,
  "the password isn't on screen" proves almost nothing, since it could be
  anywhere in a redraw), that the prompted password actually authenticates, that
  the prompt goes to stderr and never into `-o json`'s stdout, that a
  non-terminal stdin is not prompted at all (it must fail with the credentials
  error rather than block on a read nobody answers), and that Ctrl-C at the
  prompt leaves echo restored. One thing it deliberately does **not** assert:
  echo being on right after a successful prompt in the *interactive* case, by
  then the editor holds raw mode for its own read, and that is correct. The
  restore is asserted on the one-shot path, which starts no editor. Differentials:
  4 checks fail against the pre-prompt build, and a build with the SIGINT restore
  removed and the prompt moved to stdout fails exactly the three that describe
  those two properties.
- `scripts/upload-cancel-test.py <host> <user> <realm> <password>`, Ctrl-C during
  the *payload-streaming* phase. Generates a ~4 MB `.ps1` (≈92 chunks), loads it
  via `-s`, SIGINTs mid-stream, and asserts both halves: the load aborted, and the
  next command was left alone. Two harness traps this one had to learn, both of
  which made it pass against a knowingly-broken build:
  - **Never wait on quiescence here.** Chunk commands print nothing, so a shell
    mid-upload is byte-for-byte indistinguishable from an idle one. Wait for
    `canceled…|loaded …`, a fixed build prints the first, a broken one the
    second, so both builds reach the same state before anything is asserted.
  - **A probe must not contain its own answer.** `{'DEFINED'} else {'ABSENT'}`
    echoes *both* tokens, so either assertion holds no matter what the target
    says. Build the token on the target (`'PROBE-'+'DEFINED'`) and wait for that,
    not for a prompt, a long line makes the editor repaint, and the repaint puts
    a prompt in the buffer before the command has run.
  The regression assertion must also be the *first* command after the abort: any
  other command drains the stale signal itself and hides the bug.
- `scripts/transfer-edge-test.py <host> <user> <realm> <password>`, the
  transfer-engine edge cases the offline `internal/transfer` fake asserts, run
  against the real box so the fake can't quietly drift from reality: a
  multi-chunk upload (forced with `--chunk-size 4`) landing byte-exact against
  the **target's own** `Get-FileHash`, a byte-exact download round-trip, an empty
  file still being created, and the first chunk's Create mode truncating a
  pre-existing longer file on re-upload. It drives the shell's upload/download
  built-ins over piped stdin (plain reads on a non-terminal) and creates its
  remote dir relative to the shell location, so no account-specific path is baked
  in. The target-side hash is the load-bearing part: the client's own integrity
  check could pass on a build that also mis-hashes, so a check that trusted the
  client's self-report would prove nothing. Differential: rebuild with
  `writeChunk`'s `Create` replaced by `Append`, the three Create-truncates
  checks fail and the client's integrity check trips, while the multi-chunk
  round-trips (Append to a fresh file is identical) still pass. Verified on
  Forest: 10/10, and 7/10 against that mutant.

## The harnesses that need no target

Three, and they are the only ones that run in CI: the two mutation gates
(`make mutants`, one per sealing package, `ntlmseal-mutants.sh` below and
`krbseal-mutants.sh` at the end of this section) and the dumb-terminal pty test.

The last is `internal/lineedit/dumbterm_test.go`, an ordinary `go test`, so
`make check`
already runs it, which drives the shell's editor over a real pty that
deliberately **never answers** the startup `ESC[6n` cursor query. It is the
inverse of every other PTY harness in this file: those must answer the query to
work at all (the DSR trap below), which is precisely why none of them could ever
see that an unanswered query hangs the editor forever. The two ways its first draft passed for the wrong reason: waiting for the
prompt proves nothing, because the prompt is printed *before* the query is sent,
and that `TestSilentTTYSanity` (which asserts the unguarded path still hangs) is
what stops the guard cases from passing vacuously.

`scripts/ntlmseal-mutants.sh [name-substring]` is a mutation differential for
`internal/auth/ntlmseal`'s unit tests: it breaks the production code twenty
ways, one at a time, and confirms the tests notice. It runs anywhere, CI
included, and exits non-zero unless every mutant is CAUGHT.

It exists because that package's tests split into two kinds with very different
power, and only a differential shows which is carrying which mutant:

- `message_test.go` / `httpseal_test.go` recompute expected values **with the same
  primitives the production code uses**. They pin *layout*, field offsets,
  security-buffer bounds, keystream alignment, the multipart envelope, and a
  self-consistent implementation of the *wrong algorithm* passes them untouched.
- `vectors_test.go` compares against **MS-NLMP's published values** (§4.2.1
  common values, §4.2.4 NTLMv2). Independent ground truth, and the only thing
  that catches a mutant which stays self-consistent across both ends of the
  session.

Five mutants are caught **only** by the vectors: `ntowfv2` dropping
`strings.ToUpper(user)`, `wrap` signing the ciphertext instead of the plaintext,
`sealKey`/`signKey` swapping direction, `ntlmv2Temp` dropping the temp blob's
trailing `Z(4)`, and the LM response being zeroed only when a timestamp is
present. Each stays self-consistent, client and server derive the same wrong
answer, or the proof is computed over the same malformed blob it ships, so every
structural test still passes. Confirmed by moving `vectors_test.go` aside and
re-running: exactly those five go MISSED and the script exits 1 (last measured
2026-07-31). That is the differential *on the harness itself*, and it is the
reason both files exist rather than one.

The script's own header comment carries that list too, so it is a third place the
count can go stale, it had, saying three, having missed the two most recently
added. It is now dated and names all five.

Re-run that check when adding a mutant or moving a test between files, the
count drifts silently otherwise, and it has, twice. Adding the LM-response
mutant took it from six to seven with no signal. Then
`TestIntegrityFailuresAreTerminal` landed in `seal_response_test.go` and took it
from seven to five: the two `unwrap`-rejection mutants (accepting a forged
signature, ignoring the sequence number) are now caught structurally as well, so
the vectors are no longer the only thing standing between them and a MISSED.
Fewer vectors-only mutants is a *strengthening*, it means a second, independent
test would also have to be wrong, but it is only visible if the count is
re-measured rather than copied forward, which is why this paragraph exists.

Traps this harness hit, all now guarded in-script:

- **A patch that no longer matches is not a pass.** Renaming `rand.Read` to
  `randRead` silently turned one mutation into a no-op; an earlier version
  detected no-ops with `git diff`, which never fired because `ntlmseal.go`
  legitimately carried uncommitted changes, so it reported the untouched good
  build as a genuine MISSED. It now compares against a pristine backup and
  reports SKIP as a failure.
- **A mutant that does not compile re-tests nothing**, the `go build` trap from
  the ground rules, in unit-test form. Reported as INVALID, counted as failure.
  One mutation (blanking the MIC `copy`) left a variable unused and was caught
  by exactly this.
- **A filter matching nothing** would otherwise print `0/0 caught` and exit 0.
  Guarded.

One thing the vectors deliberately do *not* cover, flagged rather than invented:
MS-NLMP §4.2.4.4 publishes only the **client-to-server** sealing and signing
keys, so the server-direction pair is asserted on properties (16 bytes, differs
from the client's) instead of a made-up vector.

The other divergence from the spec's example is the **`LmChallengeResponse`**,
and the reasoning behind it was wrong the first time it was written here. The
spec's §4.2.4.2.1 computes a real LMv2 (its example challenge carries no
`MsvAvTimestamp`) and §3.3.2's `ComputeResponse` computes one unconditionally;
this code always sends `Z(24)`. The justification is *not* §3.1.5.1.2, that is
a **SHOULD, not a MUST**, and it only speaks to the timestamp-present case. The
real reason it is safe is **server-side**: §3.2.5.1.2 compares
`LmChallengeResponse` only *inside* the branch taken when the NT response
mismatches, so a valid NTLMv2 response means the field is never read; §3.4.5.1's
KXKEY discards it for NTLMv2. Samba's acceptor short-circuits identically
(`libcli/auth/ntlm_check.c`, `ntlm_password_check` returns `NT_STATUS_OK` from
the NTLMv2 branch without touching `lm_response`). That argument holds even
against an acceptor that sends no timestamp, Responder, pre-4.2.11 Samba,
which the old "every real Windows listener sends one" reasoning did not cover.

Sending a real LMv2 alongside NTLMv2 would be worse than redundant: it enabled
**CVE-2019-1338** (a DC skips NTLMv2 AV_Pair validation when an LMv2 is present,
letting a relay strip the MIC and channel bindings), it is why Samba zeroes the
field, and it is a recognisable **impacket tell**, Windows, Chromium, .NET and
Samba all put 24 zero bytes on the wire, so `Z(24)` is also the quieter choice.
Both the timestamp-present and timestamp-absent cases are pinned, and the mutant
"LM response is only zeroed when a timestamp is present" is caught by the second
of those alone.

**No test seams.** The vector needs a fixed client challenge and a zero FILETIME,
neither of which `type3` can be asked for, it draws one from `crypto/rand` and
the other from the clock. The first version of this work reached that by making
`rand.Read` and the clock package vars the test reassigned. They are gone: the
blob assembly is instead extracted into pure functions, `ntlmv2Temp`,
`ntlmv2Response`, `keyExchangeKey`, which the vector test calls directly with
MS-NLMP's inputs. `TestType3UsesTheVerifiedHelpers` closes the remaining gap by
recovering the client challenge from a real `type3` message, rebuilding the
response through those same verified functions, and requiring an exact match,
so the helpers being right and `type3` calling them right are both covered, with
no mutable global state in the auth path.

### Live-verifying the inbound signature check

The mutants and the vectors together prove `unwrap` implements MS-NLMP. Neither
can prove that a **real** Server 2016 listener's signatures satisfy it, and that
mattered here because a mismatch is deliberately terminal: if Forest's
signatures disagreed with the spec for any reason, this would break every
session rather than degrade. That is the claim the ground rules say not to take
on unit tests alone, and it was settled on Forest 2026-07-31.

`make verify` passing is necessary but *not* sufficient, a check that never ran
would pass it identically. The differential is two mutants that each make the
check reject a **valid** Windows signature, driven through `wsmancer-sealcheck` against
the live box:

| Build | Live result |
| --- | --- |
| baseline | session OK |
| `unwrap` verifies with `clientSign` instead of `serverSign` | session FAILED, `signature verification failed` |
| sequence compared against `serverSeq+1` | session FAILED, out of sequence |

Both mutants dying live is the load-bearing part: it means the real server's MAC
and sequence number were genuinely recomputed and matched, so the baseline pass
was the check *succeeding*, not the check being skipped. Re-run it with
`scripts/`-style care about build freshness, a failed `go build` leaves the
previous binary and silently re-tests the good one.

**That differential found a real bug**, which is the argument for doing it at all.
Mutant B failed, but with the wrong symptom: `XML syntax error on line 6: illegal
character code U+0010`. `unwrap` was returning a plain `fmt.Errorf` for a
sequence mismatch, so `sealed()`'s switch, which matched only `errBadSignature`,
filed it under "a body that was never really ours", handed the caller **raw
ciphertext**, and left the desynced connection open. MS-NLMP 3.4.4 and the
function's own doc comment both said such a message must be discarded; the
transport disagreed. Fixed with an `errOutOfSequence` sentinel and
`terminalUnwrapError`, which both branches now share; the live symptom is now
`ntlm: sealed message out of sequence (replayed or reordered)` and the
connection drops. The unit tests could not have seen this, `unwrap` returned
the correct error and was tested at that boundary, while the transport ignored
it, so the twentieth mutant ("out-of-sequence downgraded to a parse failure")
now pins the classification, caught only by `TestIntegrityFailuresAreTerminal`.

Enforcement is safe across re-dials because `dialAndHandshake` always builds
fresh `sessionKeys`, so RC4 handles and counters reset and keys are never reused
across a re-handshake, the usual hazard when turning inbound verification on.
`connection-break-test.py` covers that path: `state` passes with **two** NTLM
handshakes (the runspace's variable, function and cwd survive the re-dial, and
the fresh keys verify), and `blackhole` still frees the wedged read at the
backstop.

### `krbseal-mutants.sh`, the second mutation gate (2026-08-10)

`scripts/krbseal-mutants.sh [name-substring]` is the same harness shape aimed at
`internal/auth/krbseal`: fourteen mutants, one at a time, exits non-zero unless
every one is CAUGHT. Needs no target, so CI runs it (~8s).

It exists because `krbseal` gained the precondition that had until then been
`ntlmseal`'s alone, a second test style whose power differs from the first.
Before 2026-08-10 every test in `seal_test.go` built its input with the
production `wrap` and asserted `unwrap` read it back, which is blind by
construction. The RC4 path is where that bites: `krbseal` hand-rolls RFC 4757
§7.3's HMAC-MD5 chains rather than delegating to a cryptosystem, and the whole
derivation chain is *shared* between `wrapRC4` and `unwrapRC4`. Break it and you
break both ends identically, so the round-trip still closes and every test still
passes.

The measurement, first taken when the vectors landed:

| Pass | Result |
| --- | --- |
| baseline (all tests) | **14/14 caught** |
| `vectors_test.go` moved aside | 4 caught, **10 MISSED** |

The ten are every RC4 crypto mutant (nine) plus the AES key-usage swap; they are
tagged `[vectors-only]` per mutant in the script. The four that survive without
the vectors are the three tamper-check controls, deliberately included so the
measurement cannot silently stop isolating anything, plus "AES rotation runs
the wrong way at both ends", which `TestSealPlumbing` catches because it asserts
the recovered *length* as well as the prefix.

Ten of fourteen is a much more lopsided ratio than `ntlmseal`'s five of twenty,
and that is the finding, not a quirk of mutant selection: essentially the entire
RC4 algorithm was unpinned by anything that could run offline. What had been
holding it up was the live matrix against a real Windows DC, which needs an
ephemeral box.

**The ground truth is weaker in kind than `ntlmseal`'s, and the difference is
worth stating.** MS-NLMP publishes byte vectors; the RFCs publish none for these
wrap tokens. So `krbseal`'s vectors are impacket's *output*, an independent
implementation, not an authority. impacket could in principle be wrong the same
way we are. What makes that acceptable is the live matrix: agreement with a real
Windows acceptor is what says impacket and `krbseal` are both right, and the
vectors' job is to stop a future edit drifting off an agreement that has already
been demonstrated. Regenerate them with `scripts/krbseal-vectors.py` (needs
impacket; not run by CI or `make check`, the frozen bytes are the artifact).

#### Closing that leg live (Forest, 2026-08-10)

The paragraph above leans on a *transitive* claim, krbseal ≡ impacket offline,
krbseal ≡ Windows live, therefore impacket ≡ Windows for this construction, and
transitivity is only worth anything if both legs exercise the same code. That
was measured rather than assumed, on a fresh spawn (10.129.95.210, skew 408s,
tickets re-minted; the AES256 key comes from a DCSync, which is why
`get-tickets.sh` takes it as input).

`verify-matrix.sh` first: **6/6**, both must-fail controls denying. Then three
mutants, rebuilt and re-run against the live box, the point being to show the
live path is sensitive to exactly the derivations the vectors pin, and to
nothing else:

| Live mutant | RC4 row (etype 23) | AES row (etype 18) |
| --- | --- | --- |
| `Kcrypt` drops the 0xF0 xor | **FAIL** (deny) | PASS |
| `Kcrypt` inner HMAC keys on 1 | **FAIL** (deny) | PASS |
| AES seals/opens with the initiator usage | PASS | **FAIL** (deny) |

Each breaks its own etype's row and leaves the other's untouched, and each is
one of the ten `[vectors-only]` mutants offline. So the vectors and a real
Server 2016 acceptor agree on what "correct" means here, and a green matrix on
this path is not something a broken build could have produced. Both etypes were
also driven end-to-end through the actual binary (`-x whoami` over RC4;
`-o json -x whoami` over AES256), not only through `wsmancer-sealcheck`.

Two places impacket and `krbseal` legitimately differ, both handled in the
generator and documented there: impacket applies RFC 1964 padding to a multiple
of 8 and this code deliberately does not (WinRM's in-place `SECBUFFER_DATA`
encryption adds none), so the vector's plaintext length is a multiple of 8 to
make the two agree byte-for-byte; and impacket's GSS framing length counts only
the signature where WinRM's IOV layout counts the data buffer too, which is
immaterial because `unwrapRC4` finds the token by searching for the OID rather
than trusting the length.

The AES vector's independence is only **partial**, and the script says so:
impacket's AES `GSS_Wrap` hardcodes `Flags=6` and always uses
`KG_USAGE_INITIATOR_SEAL`, so it cannot express the acceptor-sealed token this
code has to read, and the generator builds the RFC 4121 header itself. What that
vector pins is the key usage, rotation direction, RRC and header layout against
an independent *cryptosystem*. The AES payload crypto is go-krb5's and is
vector-tested upstream, which is why the RC4 vector is the load-bearing one.

One trap worth repeating because this harness hit it on the first run: deleting
an integrity comparison outright orphans the values it read and the package
stops compiling, which the script reports as INVALID and counts as failure. The
controls therefore neuter the condition with `if false && ...` rather than
removing it. That is the unit-test form of the `go build` trap in the ground
rules, a mutant that does not compile re-tests nothing.

## Verifying `krbseal`'s inbound verification

The Kerberos sealing path got the same treatment as `ntlmseal`, for the same
reason and a year of calendar later. It **is** live-gated, see "Live-gating it
(Forest, 2026-08-01)" below, which is the part that matters most, because the
unit-level work above it is necessary and not sufficient.

The gap was found by coverage (`unwrap` sat at 0.0%) and confirmed with a
working exploit before anything was changed: `unwrapRC4` derived the sequence
number from the token, decrypted, and returned the plaintext without ever
recomputing RFC 4757 §7.3's SGN_CKSUM. A test that XORs `plain ^ chosen` into
the ciphertext and asserts on the *returned string* got
`"<Objs>GUEST........</Objs>"` back from a token sealed over
`"<Objs>Administrator</Objs>"`, attacker-chosen plaintext, accepted, rendered
as the target's own words. `TestRC4RejectsTamperedCiphertext` is that exploit,
kept and inverted.

Why `TestRC4RoundTrip` never saw it: a round-trip test seals and unseals its own
message, so it exercises the decrypt and nothing else. No round-trip test can
catch a missing integrity check, the tamper is the whole experiment, and a
round-trip never tampers. That is this repo's recurring failure mode in its
purest form, and worth remembering when the next "the round-trip passes" arrives.

The two etypes needed different fixes, and conflating them is the trap:

- **AES** already had payload integrity, free, from the etype's HMAC inside
  `crypto.DecryptMessage`. What it lacked was the RFC 4121 §4.2.6.2 comparison
  of the cleartext 16-byte header against the sender's echoed copy inside the
  ciphertext, without which the header's flags and sequence number are
  attacker-writable even though the payload is not.
- **RC4** had nothing, and needed both the SGN_CKSUM recompute and a direction
  tag check. The direction check is not symmetry with the AES flag: RFC 4757
  keys both directions identically, so the client's own request reflected back
  recomputes a valid checksum. AES cannot be attacked that way because the two
  directions use different key usages.

A one-off mutation differential broke each check in turn: **5 of 8 caught**, and
the three survivors are all informative rather than gaps to close. It was run
once and recorded here rather than committed, re-run it by hand if these checks
are touched.

> **Superseded in part, 2026-08-10.** There *is* now a committed
> `krbseal-mutants.sh`, and it is a standing CI gate. That is not a reversal of
> the rule this measurement produced, "never land a mutation script CI does not
> run", because it lands *with* a CI job. What changed is the precondition: the
> stated reason to withhold a second gate was that only `ntlmseal` had two test
> styles of differing power needing to be policed against each other. Adding
> `vectors_test.go` gave `krbseal` exactly that, which was always the documented
> condition for revisiting.
>
> The two differentials measure different axes and both are worth keeping. The
> 8 mutants in the table below break the integrity **checks**, does the code
> reject a bad response. The 14 in `krbseal-mutants.sh` break the
> **derivations**, does the code compute the same bytes an independent
> implementation does. Nothing in the table below would catch a wrong Kcrypt,
> and nothing in the script below would catch a deleted comparison; that is why
> the script carries three tamper-check controls.

| Mutant | Result |
| --- | --- |
| rc4: skip SGN_CKSUM compare (*the original bug*) | caught |
| rc4: checksum omits the plaintext | caught |
| rc4: skip direction tag | caught |
| aes: skip echoed-header compare | caught |
| aes: decrypt error not classified `errBadSignature` | caught |
| rc4: compare only 1 of 8 checksum bytes | MISSED, a 1-byte compare still rejects 255/256 tampers, so no small test catches it deterministically. Left standing knowingly. |
| aes: skip `SentByAcceptor`/`Sealed` flags | MISSED, **by design**: subsumed by the echoed-header compare and the usage split. |
| aes: skip TOK_ID check | MISSED, same; both are early rejects for a better message, and the code comment now says so rather than reading as load-bearing. |

Those last two are the reason the differential was worth running: it is what
distinguishes a check that provides a guarantee from one that provides an error
message, and both kinds are in the file. The comments were rewritten to match
what the differential showed, not what the checks look like they do.

### Live-gating it (Forest, 2026-08-01)

Everything above is unit-level, and two of the new rejections assert things about
what a *real Windows listener* emits, so a wrong assumption would not weaken a
check, it would **break an auth mode**, refusing every sealed response:

1. that Windows sets the RFC 1964 direction tag to `ffffffff` on acceptor
   tokens (RC4 / etype 23), and
2. that its echoed AES header matches the cleartext one in flags and sequence
   number.

`verify-matrix.sh` settles both at once, because the baseline *demands* them:
**6/6**, unsealed-refused controls included, on `forest.htb.local`. One run
covers both etypes (the etype follows the ccache's principal, not the
krb5.conf), which is exactly why those two rows exist.

But a green matrix is necessary and **not sufficient**, a build with the checks
deleted passes it identically, because the checks only ever reject. So the
`ntlmseal` method applies: mutants that make a check reject a *valid* Windows
response, driven through `wsmancer-sealcheck`. A mutant that still gets a session means
the check never ran.

| Build | Live result |
| --- | --- |
| baseline RC4 (etype 23) | session OK |
| baseline AES256 (etype 18) | session OK |
| RC4 checksum keyed with a wrong `Ksign` string | session FAILED |
| AES echoed-header comparison inverted | session FAILED, `refusing response … echoed header 050403ff…` |
| AES *also* requiring `echoed[4:8]==hdr[4:8]` | session FAILED |

The first two mutants dying is the load-bearing part: the RC4 SGN_CKSUM and the
AES echoed-header compare were genuinely recomputed against the real server's
output, so the baseline pass is the check *succeeding*, not the check being
skipped.

The third was a probe rather than a control, and it answered an open question.
Forest's echoed header is `050403ff` `00000000` `0000000000000000`: TOK_ID
`0504`, flags `0x03` (`SentByAcceptor|Sealed`, so Windows does set the acceptor
bit), and EC/RRC **zero** in the echoed copy while the cleartext header carries
the real RRC. That is why bytes 4:8 are excluded from the comparison, now on
evidence rather than on reasoning; it also means the RFC's stricter "echoed
EC/RRC must be zero" form would work here, and the code comment records why it
is still not adopted.

**Harness trap this hit**, worth repeating because it is the generic one: the
first run wrapped a shell *function* in `timeout`, which cannot invoke one, so
every invocation errored, every mutant "failed as expected", and the differential
reported a clean sweep while testing nothing. The two baseline rows are what
caught it, they are in the table for exactly that reason, and any live
differential written here should keep a row that must come back **ok**.

### What this does *not* buy: freshness (measured, 2026-08-01)

The checks above give Kerberos sealing **integrity**, not **replay protection**,
and `ntlmseal` is not a template here. That path refuses a message whose
sequence number is not the one it expects (`declared != k.serverSeq`, terminal).
`krbseal` has no receive-side counter at all, and the reason is measured rather
than assumed: instrumenting `unwrap` to log the acceptor's sequence across a
session gives, for **both** etypes,

```
[SEQPROBE] rc4 recv seq=0 dir=ffffffff (our next send seq=1)
...
[SEQPROBE] rc4 recv seq=0 dir=ffffffff (our next send seq=10)
```

The server's sequence number is **constant zero** while ours climbs 1→10. So an
`expected++` check is not merely unimplemented, it is *impossible* against this
listener, it would refuse the second response of every session. Do not "fix"
this by mirroring the NTLM code; re-run the probe first if you doubt it.

Consequence, for the sealing layer taken alone: a captured sealed response can be
replayed or substituted and will verify, because everything the checks look at
(checksum, direction tag, echoed header) is satisfied by a genuine older
message. That is a strictly smaller hole than the one closed above, an attacker
can only replay what the server really said, not choose new text, but within
`krbseal` it is open, and it cannot be closed there.

**The fix is a layer up**, and is the section below. WS-Addressing already
carries the correlator: the client stamps each request with a random
`MessageID`, and Forest echoes it back as `RelatesTo` on **every** response,
faults included,

```
RelatesTo>uuid:A1432EDF-...</a:RelatesTo> ... <rsp:ReceiveResponse>
RelatesTo>uuid:DC61E4FB-...</a:RelatesTo> ... <s:Fault>
```

Checking it gives freshness for both auth mechanisms at once, independent of the
sealing layer, which is why the answer to "why does `krbseal` not do what
`ntlmseal` does" is not "add a counter to `krbseal`" but "the correlation lives
in `wsman`".

The trap that shaped the implementation: the fork generates that ID
inconsistently, `Delete` uses `uuid.New().String()` while every other call site
wraps it in `strings.ToUpper`, and the observed responses echo the case they were
given. **The comparison must be case-insensitive**, or that call site rejects its
own server's reply. Nothing live reaches it (see the limit recorded below), so
`TestRelatesToIsCaseInsensitive` is the only guard.

### Implemented and live-gated (Forest, 2026-08-01)

`checkRelatesTo` in `wsman/client.go`, called from `sendEnvelope`, the single
choke point all 11 request methods funnel through, so no path opts out. A
missing `RelatesTo` is a **failure, not a skip**: treating absence as "nothing to
check" would let an attacker disable it by stripping one header.

The check runs on every exchange, which was proven rather than assumed, a
mutant that can never match dies on the first request:

```
Error: connect: init backend: create shell: wsman: response does not correlate
to the request: got RelatesTo "uuid:2FB71CAC-…", sent MessageID "uuid:2FB71CAC-…"
```

so the baseline passing is the check *succeeding*. Live paths re-verified with it
in place: NTLM, Kerberos RC4 and Kerberos AES sessions; `batch-test.py` 16/16;
`transfer-edge-test.py` 10/10; `ctrlc-latency.py` (median 0.69s, unchanged);
`connection-break-test.py` `idle` and `state` 1/1 each.

**The case-insensitivity has no live gate, and cannot have one.** The mutant that
makes the compare case-sensitive was built and run against Forest: *nothing
failed*. The reason is that the only lowercase call site is `Delete`, which is
reached solely from `client.RemoveDisconnectedSession`, a path wsmancer
never calls. So it is a latent trap, not an active bug, and
`TestRelatesToIsCaseInsensitive` is the only thing standing between it and a
future regression. That asymmetry is the point of recording it here: a live
harness *cannot* catch this one, so do not treat the unit test as redundant.

Unaffected but noticed while doing this: `connection-break-test.py running`
fails 2/3, the in-flight command completes instead of being lost, and the
"connection to the target dropped" message never appears. **This is pre-existing
on `main`**, confirmed by re-running the same scenario against a stashed
baseline build (identical 1/3). It is not caused by the correlation check.
**Resolved 2026-08-02: the harness expectation is stale**, the measurement and
its caveats are two sections down; the code trace that predicted it is first.

**What the code trace predicts.** The transport is *built* to make a loud RST
invisible:

- `connRoundTripper.RoundTrip` (`ntlmseal.go:442`, `krbseal.go:635`) drains the
  request body into `plain` *before* its 2-attempt loop, the body is buffered
  for the express purpose of replaying it. On a write or read error it calls
  `closeConn`, re-dials, re-handshakes and **replays the same request**.
- `closeConn` (`ntlmseal.go:482`) nils `keys` as well as the conn, so the replay
  is re-sealed from sequence 0 rather than reusing a desynced keystream.
- Nothing above it is touched: `ShellId`, `SessionId` and `CommandId` live in
  `wsman.Client`/`powershell.WSManTransport`, so the replayed `Receive` carries
  the identical selectors, and the identical `MessageID`, which is why
  `checkRelatesTo` still matches a replayed envelope.
- `WSManTransport.Read` (`powershell/transport.go:79`) is an unbounded poll loop
  that only exits on `Done` or an error, so if the replay succeeds the still-
  running pipeline's output simply keeps arriving.

So the *design intent* is that a mid-flight RST recovers transparently.

### Measured (Forest, 2026-08-02): the command survives, 17/17

Driven through `break-proxy.py` on a modified copy of the harness that
**records** the outcome rather than asserting the old expectation, across break
offsets 1.2s / 3.0s / 3.25s / 3.5s / 3.75s / 4.0s / 6s / 8s:

```
OUTCOME survived=True reported=False   (x17, every offset)
-- transport: 2 NTLM handshakes, 1 failed requests --
[proxy] conn #1 established / KILLED 1 connection(s) with RST / conn #2 established
```

> **Unreconciled count.** `connection-break-test.py:149` records this same
> 2026-08-02 measurement as **21/21** across the same 1.2s-8s offsets, and the
> paragraph below refers to "21 runs". Whether 17 and 21 are two populations
> (the offset sweep versus every run of the day, which would also cover the
> 8 runs with the pty read) or one of them is a miscount is **not settled**, and
> cannot be without a live re-run. Neither figure changes the conclusion, every
> run in both counts survived, but do not quote either as exact until someone
> re-measures and collapses this note.

The `conn #2` and the second handshake are the load-bearing part: the break
really happened and the transport really re-dialled, so the completion is the
replay working, not the kill being missed. **The harness expectation is stale**: the old "mid-command → that command is
lost" measurement no longer holds. There is no timing window: 3.0s and
3.5s each pass repeatedly, and the offsets bracket the 1s Receive poll.

### Why it survives: the output is not streamed (measured at the proxy)

The mid-stream question that hung over the result above is **settled, and the
premise was wrong**. Instrumenting the proxy to timestamp server→client bytes,
a 20s command's traffic is `~1800 bytes every ~1.05s`, and the decisive part is
the control: a **silent** `Start-Sleep -Seconds 20` produces the *same* steady
1800-byte chunks. Those are empty poll responses, not data. The 40 tokens of a
"streaming" command all arrive in one final chunk (2844 bytes at t=23.94s).

So this shell never streams: PowerShell renders the result remotely
(`Out-String`) and it crosses the wire as a single burst at pipeline completion.
A break before that has **nothing to destroy**, which is why the replay always
wins, not luck, and not a narrow window that 21 runs happened to miss.

The earlier "streaming" control was **vacuous**, and it is worth keeping the
record of why: it looked for output *before* the break, found none, and so
re-tested the silent case under another name. A later probe fixed that by
asserting on **completeness after recovery** (all 40 tokens present, control run
with no break to prove the assertion could fail), that probe passes 40/40 both
with and without a break, consistent with the byte timeline above.

**The one window that can destroy output is the burst itself**, and it behaves
correctly. Aimed at it through `-x` (kill verified to have severed a live
connection, not one that had already closed, four earlier attempts killed
*nothing* and produced four meaningless passes), the result is:

```
EXIT=1
Error: connection to the target dropped; this command was lost.
   The session reconnects automatically, run it again.
```

Lost, and **reported**, never a silent empty result, which is the outcome that
would actually mislead an operator into reading "no output" as "found nothing".

**A `burst` scenario for `connection-break-test.py` was written and withdrawn.**
From the interactive harness the break never landed in the window: offsets
19.6 / 20.9 / 21.5 / 22.0 / 22.5s all had the command complete anyway, even
though the trace confirms the connection really was severed each time. That is
itself an unexplained difference from the `-x` path, where a break at a
comparable point loses the result, worth chasing if anyone needs the window
covered by a harness. It was withdrawn rather than shipped because it reported
`INCONCLUSIVE` on every run while still printing `1/1 checks passed`, which
reads as green. **A scenario that cannot land is worse than no scenario.**

### The RST that is not delivered, benign, and it is the backstop path

Reading the pty for 0.5s immediately *before* triggering the break makes the
client miss the RST entirely: `1 NTLM handshake, 0 failed requests`, no re-dial,
the command lost, no drop reported, and no recovery inside the harness's ~105s
of waiting. Deterministic, 8/8 runs with that read, 17/17 without it. It is
**not** the ~0.5s shift in break timing; that was the first hypothesis and the
offset sweep above disproves it.

A `SIGQUIT` dump (`WSM_DUMP_ON_HANG=1`) settles what the client is doing:

```
net.(*conn).Read <- bufio.(*Reader).fill <- http.ReadResponse
  <- ntlmseal.(*connRoundTripper).write (ntlmseal.go:678) <- sealed <- RoundTrip
[IO wait]
```

That is the **blackhole** signature, character for character. The client is not ignoring a break,
no break ever reached it. So the correct expectation is not a fast re-dial but
the `deadCommsBackstop`, and re-running with a 200s wait confirms it exactly:

```
OUTCOME survived=False reported=True     <- the loss IS reported
  PASS  the NEXT command works (session recovered)
transport: 4 NTLM handshakes, 3 failed requests
```

**So there is no defect here.** The backstop fires at 120s, the transport
re-dials, the loss is reported and the session recovers, the safety net working
as designed. `connection-break-test.py running` waits less than 120s, which is
the whole of why it looked like a hang. The scenario now prints a `NOTE` when it
sees this shape (both checks failing with a single handshake) rather than
leaving the next person to rediscover it.

#### Root cause: the harness ate the client's cursor query (2026-08-02)

**This supersedes the proxy explanation below, which was a mis-attribution.**
The cause is the DSR trap in a subtler form, and it is proven by intervention
rather than inferred.

Dumping what the client emits mid-command shows it redrawing its prompt and
ending with a cursor query:

```
b'...\x1b[34mPS \x1b[0mC:\\Users\\svc-alfresco\\Documents> \x1b[6n'
```

A "drain" read consumes that query and never answers it, so the client blocks in
`GetCursorPos`, the same no-timeout wait that hangs a dumb terminal, reached by a different route: not a terminal
that *cannot* answer, but a harness that *ate the answer*. The intervention is
decisive:

| pre-break action | result |
| --- | --- |
| swallow the query, do not answer | **fails**, 1 handshake |
| swallow it, then write `ESC[24;1R` anyway | **passes**, 2 handshakes |

Answering a query the harness had already eaten restores the whole behavior.
Base rates confirm it is deterministic rather than flaky: interleaved,
`none` passed 4/4 and the swallowing mode failed 4/4.

It cascades: a wedged `GetCursorPos` blocks the output path, the receive loop
stops draining the socket, and `ss` catches the proxy holding an unread
`ESTAB 0 3208` send queue. **That is why the connection looked unsevered**, the
client was not reading it, not because the proxy failed to kill it. The
socket-state reading below was a symptom mistaken for a cause.

Note the trap inside the trap: answering DSR *in general* is not enough.
`expect()` does answer, and the original probe still failed, because a read
window that ends between a query and its answer swallows that one. **A harness
read that discards is never safe.**

#### (superseded) The socket-state reading that pointed at the proxy

Isolating the probe's three effects, extra delay, printing to the harness's own
stdout, and *reading the pty*, pins it on the read alone:

| pre-break action | survived | handshakes |
| --- | --- | --- |
| nothing | yes | 2 |
| `sleep(0.5)` | yes | 2 |
| `print(...)` | yes | 2 |
| read pty 0.5s, **not** answering DSR | **no** | 1 |
| read pty 0.5s, answering DSR | **no** | 1 |

Answering the cursor query is not the trigger (`readnodsr` fails identically);
the client does emit during the command, 105 bytes in that window unanswered, or
7551 if you answer and provoke a redraw.

`ss -tan` across the break then settles who is at fault:

- **failing run**, the client keeps *one* port (`127.0.0.1:38392`) for 59 of 60
  samples spanning the kill. Both ends stay `ESTAB`.
- **passing run**, two ports, `38264` then `39872`: the connection really died
  and the client re-dialled.

So in the failing case **the connection is never severed**. `break-proxy.py`'s
`close()` with `SO_LINGER 0` does not always sever a socket another thread is
blocked in, closing such a socket is undefined in CPython, and the relay stops
while both ends remain established. That is the definition of a **blackhole**,
so the client parking until `deadCommsBackstop` is not merely acceptable, it is
the *correct* response to what actually happened. There was never a client-side
fault to explain.

**A `fileno()`-based verifier in the proxy does not detect this.** It was written
and withdrawn: it reports `all sockets closed` in the failing run too, because
the Python object closes while the TCP connection stays up. Anything verifying a
sever has to observe TCP state (`ss`) or the peer re-dialling, the proxy's own
`conn #N established` counter mirrors the latter, which is why the harness-side
"the transport re-dialled" check is the one that works.

**The general rule this yields:** any harness asserting on a connection break
must either wait past the 120s backstop or treat a missing re-dial as
inconclusive. Asserting recovery inside 105s makes the test flaky by
construction. Chased in the wrong order once already, blamed first on a tired
box (14 leaked shells; cleaning them changed nothing), then reported as a
product defect, before the differential identified the harness. Run the
differential first.

**`running` has been rewritten** (2026-08-02) and now asserts what is true: the
command **survives** a break in its quiet phase. Verified live, 3/3, alongside
`idle` 1/1 and `state` 1/1 on the same build.

Its second assertion is the one to keep whatever else changes, *the transport
re-dialled (≥2 `leg1` handshakes in the trace)*. Surviving is only evidence if
the break actually severed a live connection, and a kill that hits nothing
leaves an untouched session that satisfies the first assertion for entirely the
wrong reason. That is not hypothetical: it is exactly how four runs of this
measurement produced four confident, meaningless passes.

## Verifying `certauth`

Needs the target configured in advance, a certificate maps to an account only
because someone said so, which is why the setup is a script rather than a
README paragraph:

```sh
# The mapped account has no default, a mapping only means anything against a
# real account on your own target.
export MAP_USER='HTB\svc-alfresco' MAP_UPN='svc-alfresco@htb.local' MAP_PASS='...'

scripts/certauth-setup.sh forest.htb.local Administrator <nthash> /tmp/ca-lab
source /tmp/ca-lab/env.sh
scripts/certauth-test.py Administrator <nthash>
scripts/certauth-setup.sh forest.htb.local Administrator <nthash> /tmp/ca-lab --teardown
```

Setup mints two certificate pairs (one issued by a CA the target trusts, one
identical but from a CA it does not), stands up the HTTPS listener, enables
`Service\Auth\Certificate`, imports the CA and writes the mapping; teardown
reverses all of it. Note `New-Item` on a WSMan listener does **not** replace an
existing one, it fails, so setup deletes first, or a second run dies.

The harness is 16 checks and the positive result is only believed alongside two
controls that must fail: the rogue certificate (same subject, same UPN, same
EKU, different issuer, so a target that accepts it is not checking the chain)
and *removing the mapping*, after which the same certificate must be refused
401. It also asserts that a certificate **plus** a password still authenticates
over NTLM, which is the divergence from upstream that would otherwise be easy to
delete by accident. Verified on Forest: 16/16; mutants confirm each claim, no
`Authorization` header ⇒ 401, no renegotiation ⇒ `tls: no renegotiation`, and
pooled connections ⇒ still 16/16, which is what corrected the single-connection
rationale in `docs/architecture.md`.

Two field notes that contradict what the documentation implies. Cert-auth
mappings are widely described as requiring a **local** account; on Forest, a
**domain** account mapping was created and authenticated fine, on a DC, where
local accounts do not exist at all. And the mapped account is who you become:
the harness never passes `-u`, and `whoami` returns the mapped user.

## Verifying `donut-loader`

Needs a sacrificial process and an observable payload. Use benign shellcode with
no callback, `msfvenom -p windows/x64/exec CMD='cmd.exe /c echo PROOF >
C:\Windows\Temp\proof.txt' EXITFUNC=thread -f raw`, then inject and check the
file. **Harness trap:** a process started with `Start-Process` from a WinRM
session is torn down when that session ends, so it looks like the injection
killed the host. Spawn it detached instead (`Invoke-WmiMethod -Class
Win32_Process -Name Create ...`, which needs an admin account, pass-the-hash is
fine) and control for it by checking the process survives on its own *before*
injecting. Verified this way against Forest: the payload ran inside the target
and the host process survived. Clean up the proof file and the sacrificial
process afterwards.

## Cross-cutting harness traps

**Any script driving a bare `pty.openpty()` must answer the terminal's DSR
query.** reeflective asks for the cursor position with `ESC[6n` at the start of
every read, and a raw PTY pair has nothing to answer it, so the reader blocks,
which looks exactly like a transport hang and will send you chasing the wrong
bug. Every PTY harness here answers it in its read loop
(`if DSR.search(c): os.write(master, b'\x1b[24;1R')`); a new one must too. This
used to be avoidable by pinning `WSMANCER_EDITOR=liner`, which is why the
harnesses that don't care about the editor once did, that escape hatch is gone
with liner.

**A live mutant harness must not restore with `git checkout --`.** The obvious
way to undo a mutation is to check the file out again, and it is wrong whenever
the fix under test is still uncommitted: it reverts the mutation *and* the work,
silently. That happened during the inbound-verification run above, the fix
vanished mid-session, and everything kept passing, because `make check` and
`make mutants` had already run against it and the later live scenarios exercised
paths the fix does not change. It surfaced only when an unrelated experiment hit
`undefined: terminalUnwrapError`. Restore from a `mktemp` copy taken at script
start, the way `ntlmseal-mutants.sh` does, and have the script assert the fix is
present in the source before it starts (`grep -q`). Anything already run against
a reverted tree has to be re-run: `state`, `blackhole` and `make verify` all
were.

**Provoking a WSMan SOAP fault** (to see what `describeBody` prints) needs no
second session, have the session delete its own shell and the pending Receive
faults at HTTP 500:

```sh
./wsmancer -i forest.htb.local -u svc-alfresco -r htb.local -p "$PASS" \
  -x '$s = Get-WSManInstance -ResourceURI shell -Enumerate; Remove-WSManInstance -ResourceURI shell -SelectorSet @{ShellId=$s.ShellId}'
```

Verified this way: one `wsman fault: s:Sender: w:InvalidSelectors: … the shell
was not found … code=2150858843` line, against ~1.8 KB of envelope from a build
with the summary disabled. The command tidies up after itself (it removes the
only shell there was), so nothing is left behind.

Testing also **leaks server-side shells**: a killed test process leaves its shell
alive until the PT30M IdleTimeout. Check with
`Get-WSManInstance -ResourceURI shell -Enumerate` and clean up with
`Remove-WSManInstance` if a box starts behaving oddly after a long session.

## The lab box, and the HTTPS/5986 path

These have been validated against the HTB **Forest** DC (a stock Server 2016
listener). It's an ephemeral box, so the IP changes each spawn.

Testing the **HTTPS/5986** path needs a box that actually runs an HTTPS listener,
Forest ships only 5985. To stand one up on a box you own (as Administrator):

```powershell
$c = New-SelfSignedCertificate -DnsName <fqdn> -CertStoreLocation Cert:\LocalMachine\My
New-Item WSMan:\localhost\Listener -Transport HTTPS -Address * -CertificateThumbPrint $c.Thumbprint -Force
New-NetFirewallRule -DisplayName WinRM-HTTPS-5986 -Direction Inbound -LocalPort 5986 -Protocol TCP -Action Allow
# the SHA-256 --accept-fingerprint expects (NOT the SHA-1 thumbprint):
[BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($c.RawData)).Replace('-','')
```

Then exercise all five modes over `-S`: default (rejects self-signed),
`--accept-fingerprint` right/wrong, `--insecure`, `--ca-cert <pem>`. All five
were live-verified this way; needs Administrator (a normal user can't bind a
listener), and a revert wipes it.
