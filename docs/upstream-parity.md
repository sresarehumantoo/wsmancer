# Parity with upstream evil-winrm, and the port's own history

Where this port stands against the Ruby original, which divergences are
deliberate, and the decisions behind the post-ex stack. `CONTRIBUTING.md`
summarises the status; this file is the detail. Re-check parity against
upstream's **source** (`evil-winrm.rb`), not against these notes, the two
drift.

## Every upstream command is ported

**Every post-ex command upstream evil-winrm v3.9 ships is ported**;
`notImplemented` is kept but empty, because it is how `help` tells the truth
about the port, a borrowed feature should be listed there before it works
rather than failing silently. (Upstream v3.9 has no `Dll-Loader`; an earlier
version of this note listed a `dll-loader` / `l04d3r-load-assembly` that don't
exist upstream, corrected.) The built-ins (`services`, `menu`, `upload`, …)
work in one-shot mode too: `-x` runs its line through the *same* dispatch as the
interactive shell, so anything typeable at the prompt has a `-x` form, this is a
divergence from upstream, which has no non-interactive mode at all. The
consequence is that built-ins shadow their remote namesakes in `-x` as well
(`-x help` is the port's, `-x 'Get-Help …'` is the target's). `-x -` extends this
to a **batch**: a stream of commands from stdin over one connection with the
runspace persisting between them, also port-only, and the interface built for an
agent (see `docs/json-output.md`).

**Parity as checked against upstream's source**: every built-in is ported, every
one of upstream's 20 flags exists here, plus this port's own (`-x`, `-o`,
`-Y/--history`, `--history-tag`, the three TLS-verification flags, `--skew`,
`--chunk-size`, `--proxy`), and all four auth modes including **certificate
authentication**. Nothing upstream does is missing.

## Deliberate divergences

Two are deliberate rather than missing: history is opt-in here (`-Y`) where
upstream always writes `~/.evil-winrm/history/<host>_<user>.hist`, and the log
directory differs.

A third is a superset: with `-c/-k`, upstream *always* does cert auth and ignores
any `-u/-p`; here credentials present mean NTLM/Kerberos with the certificate
along for the TLS handshake (mutual TLS, which upstream cannot express), and only
their absence makes the certificate the credential. `AuthMode` is where that is
decided. `scripts/certauth-test.py` asserts this specific divergence, because it
would otherwise be easy to delete by accident.

Two more, per-feature, documented where they live: `sendB64Var` chunks
`donut-loader`'s payload where upstream inlines the whole base64 into one command
(which overruns `MaxEnvelopeSizekb` for any real payload), and `krbseal`'s
`ticket.go` parses a kirbi in memory where upstream shells out to impacket's
`ticketConverter.py`. See `docs/architecture.md`.

One upstream **bug** is fixed rather than reproduced: upstream's Bypass-4MSI
passes an `IntPtr` to a `GetProcAddress` overload that takes a `HandleRef` on
Server 2016, so it never patches anything. Details in `docs/architecture.md`.

## The post-ex stack, in the order it was built

Low effort/high value first:

1. `-s` script loading, base64+chunk a local `.ps1` into the session, like
   upload.
2. `menu`, enumerates remote functions and feeds them to `internal/complete`
   for Tab-completion.
3. `invoke-binary`, base64+chunk a local .NET assembly into a global, then run
   it through the embedded CyberVaca loader; `internal/shell/invokebinary.go`
   and the `assets/invoke-binary.ps1` wrapper.
4. `donut-loader`, base64+chunk a local donut `.bin` and inject it into a
   remote PID via the embedded x64 loader; x64 targets only,
   `internal/shell/donutloader.go` + `assets/donut-loader.ps1`.
5. `bypass-4msi`, the AMSI patch, most detection-prone; deliberately built last,
   and nothing else depends on it, `internal/shell/bypass4msi.go` +
   `assets/bypass-4msi.ps1.tmpl`.

## Closed gaps worth not re-opening

**`--proxy`'s routing weakness is closed.** The network-namespace harness
(`proxy-test.py --netns`) now proves the isolation property the live checks used
to rely on a written control for, the client runs in a namespace whose only
route out is the proxy, so a direct-dialling build gets `network is unreachable`
and physically cannot pass. Verified 3/3, and the mutant (dialer ignores
`--proxy`) fails exactly the positive check. The three tunnel-only paths, file
transfer, Ctrl-C, and an idle session, are covered too (`tunnel_path_checks`,
base run 23/23), each asserting the proxy carried the session; the direct-dial
mutant fails exactly the three "carried by the proxy" checks. `--proxy` has no
outstanding testing gap. Both are described with the entry for
`scripts/proxy-test.py` in `docs/verification.md`.

**The `peterh/liner` fallback is gone**, it was kept for one release behind
`WSMANCER_EDITOR=liner`, and with it went the dependency, the second code path
in the editor and the history wiring, and the second PTY harness (the two are now
one `scripts/pty-test.py`). `WSMANCER_EDITOR=liner` no longer does anything,
though the variable itself came back in 2026-08 as `WSMANCER_EDITOR=plain`,
selecting the *plain reader* rather than a second editor, so the one-editor
property this removal bought still holds. The
consequence for harnesses: pinning liner used to be the way to avoid the PTY DSR
trap, so every PTY harness must now answer the cursor query itself, see
`docs/verification.md`.
