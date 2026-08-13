package shell

import (
	"context"
	"strings"
	"time"

	"github.com/sresarehumantoo/wsmancer/internal/output"
)

// remoteCommandScript lists every command the target can run, cmdlets,
// functions, aliases and applications alike, which is exactly the set a real
// PowerShell console completes. Projecting to $_.Name mirrors the two existing
// remote listers rather than relying on how a CommandInfo stringifies.
//
// A broken module makes Get-Command emit error records for that module while
// still returning everything else, so errors are tolerated as long as names came
// back (see remoteCommandNames).
const remoteCommandScript = `Get-Command -ErrorAction SilentlyContinue | ForEach-Object { $_.Name }`

// remoteCommandTimeout bounds the one fetch. It matches the budget RemotePaths
// uses for a directory listing: Tab must never make the prompt hang, so a target
// that cannot answer in time simply yields no cmdlet candidates.
const remoteCommandTimeout = 5 * time.Second

// remoteCommandRetry is how long to wait before trying again after a failed
// fetch. Latching the failure for the whole session would let one transport
// hiccup cost the operator cmdlet completion until they reconnect; retrying on
// every Tab would instead pay the timeout over and over. A cooldown does neither.
const remoteCommandRetry = 30 * time.Second

// remoteCommandNames returns the target's command names, fetching them once and
// caching them for the session. ~1900 names on a stock Server 2016 box, one
// ~0.4s round trip, after which filtering is local and instant, which is why
// this is a cache rather than a per-keystroke query.
//
// It never returns an error: a failure means no cmdlet candidates, never a
// disturbed prompt. The shell's own built-ins are added separately by the
// caller, so they keep completing regardless.
func (sh *Shell) remoteCommandNames() []string {
	// -N/--no-rpath-completion promises to disable remote completion entirely,
	// not merely remote *paths*, so it suppresses these candidates outright,
	// even a cache warmed before the check, since the flag is about what the
	// operator is willing to offer, not about saving a round trip.
	if sh.o == nil || sh.o.NoRPath {
		return nil
	}
	// The cache is just data; only *filling* it needs a session. Checking the
	// session first would make a warm cache unusable, which is both wrong and
	// untestable without a live target.
	if len(sh.remoteCmds) > 0 {
		return sh.remoteCmds
	}
	if sh.s == nil || !sh.commandFetchDue() {
		return nil
	}
	sh.remoteCmdsAt = time.Now()

	ctx, cancel := context.WithTimeout(context.Background(), remoteCommandTimeout)
	defer cancel()
	res, err := sh.s.RunRaw(ctx, remoteCommandScript)
	if err != nil || res == nil {
		return nil
	}
	var names []string
	for _, v := range res.Output {
		for _, ln := range strings.Split(output.Text(v), "\n") {
			if s := strings.TrimSpace(ln); s != "" {
				names = append(names, s)
			}
		}
	}
	// Deliberately not gated on res.Errors: a single unloadable module produces
	// error records alongside a perfectly good list, and dropping the list then
	// would cost completion on exactly the crusty boxes it helps most.
	sh.remoteCmds = names
	return names
}

// commandFetchDue reports whether enough time has passed since the last failed
// attempt to try again. Split out from remoteCommandNames so the back-off policy
// is testable on its own, without a session to fetch through.
func (sh *Shell) commandFetchDue() bool {
	return sh.remoteCmdsAt.IsZero() || time.Since(sh.remoteCmdsAt) >= remoteCommandRetry
}

// invalidateRemoteCommands drops the cache so the next completion refetches it.
// Called from `menu`, the operator's explicit "re-read what this session can
// run" action, the moment after an Import-Module or a script load when the
// command surface may have grown.
func (sh *Shell) invalidateRemoteCommands() {
	sh.remoteCmds = nil
	sh.remoteCmdsAt = time.Time{}
}
