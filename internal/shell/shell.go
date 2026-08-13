// Package shell is the interactive REPL: the command loop, prompt, built-in
// dispatch, file transfer, completion and both output modes.
//
// Every post-exploitation command upstream evil-winrm ships is implemented. The
// notImplemented map is retained (empty) because it is how `help` tells the
// truth about the port, a borrowed feature should be listed there before it
// works, rather than failing silently.
package shell

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/smnsjas/go-psrp/client"

	"github.com/sresarehumantoo/wsmancer/internal/cli"
	"github.com/sresarehumantoo/wsmancer/internal/complete"
	"github.com/sresarehumantoo/wsmancer/internal/history"
	"github.com/sresarehumantoo/wsmancer/internal/lineedit"
	"github.com/sresarehumantoo/wsmancer/internal/output"
	"github.com/sresarehumantoo/wsmancer/internal/session"
	"github.com/sresarehumantoo/wsmancer/internal/transcript"
	"github.com/sresarehumantoo/wsmancer/internal/transfer"
)

type Shell struct {
	s    *session.Session
	o    *cli.Options
	c    output.Colors
	ed   lineedit.Editor
	out  io.Writer
	json bool
	tty  bool // progress bars only make sense on a terminal
	tx   *transfer.Client
	log  *transcript.Log // nil unless -l/--log; all methods are nil-safe
	hist *history.Store  // nil unless -Y/--history; all methods are nil-safe

	cwd string

	// Post-ex: baseline is the runspace's function names before any script load;
	// loadedFuncs is what the operator has since imported (shown by `menu`,
	// offered for Tab-completion). baseline is nil until first captured.
	baseline    map[string]bool
	loadedFuncs []string

	// remoteCmds caches the target's command names for first-word completion;
	// remoteCmdsAt is when the last fetch was attempted, so a failure backs off
	// instead of latching or retrying on every Tab. Both are touched only from
	// the Run loop goroutine (completion happens inside Prompt), so no lock.
	remoteCmds   []string
	remoteCmdsAt time.Time

	// psFailedAt is when TabExpansion2 last failed, so a target that has none
	// (ConstrainedLanguage, JEA) costs one timeout rather than one per Tab.
	psFailedAt time.Time

	// invokeBinaryLoaded / donutLoaderLoaded are set once the respective post-ex
	// wrapper has been defined in the runspace, so each is sent at most once per
	// session.
	invokeBinaryLoaded bool
	donutLoaderLoaded  bool

	// amsiPatched records that bypass-4msi has run, so a second invocation says
	// so instead of re-patching bytes that are already patched (and whose helper
	// functions the payload removed on its way out). Mirrors upstream.
	amsiPatched bool

	// once marks a -x shell: one command, then the process exits. It changes two
	// things, both because there is no next prompt to serve, a forgotten shell
	// is reported rather than recovered onto (see reportErr), and failed carries
	// the exit code out.
	once bool

	// failed records that the last command did not succeed, including the ways
	// that produce no error value: a PowerShell error record (res.HadErrors), a
	// pipeline canceled by Ctrl-C, or a transport fault that was reported and
	// swallowed. Written by executeAs and reportErr, read only by Once, the
	// interactive loop shows failure rather than returning it.
	failed bool

	// reqID is the correlation token for the command currently being dispatched,
	// set by Batch when a line arrived as a JSON request object carrying an "id"
	// and cleared after each command. Every -o json object emitted for that
	// command (a result, an error, a transfer summary) echoes it, so a consumer
	// can match a response to the request it issued. nil for a bare-line command,
	// which then omits the field.
	reqID interface{}
}

// emitResult stamps the current request id onto a -o json result and renders it,
// so id correlation lives in one place rather than at every call site.
func (sh *Shell) emitResult(jr output.JSONResult) error {
	jr.ID = sh.reqID
	return output.RenderJSON(sh.out, jr)
}

// emitError renders a -o json error object for the current command, carrying the
// request id like emitResult. It is the id-aware form of output.JSONError.
func (sh *Shell) emitError(cmd string, err error) error {
	return output.RenderJSON(sh.out, output.JSONResult{
		Type:      output.TypeError,
		ID:        sh.reqID,
		Command:   cmd,
		Output:    []interface{}{},
		Errors:    []interface{}{err.Error()},
		HadErrors: true,
	})
}

func New(s *session.Session, o *cli.Options, stdin io.Reader, stdout io.Writer) *Shell {
	sh := newShell(s, o, stdout)
	// -Y/--history opts into an on-disk history. It is opened before the editor
	// because the editor takes it as its history source; a failure degrades to
	// the memory-only default rather than abandoning a working shell, matching
	// how a failed transcript is handled.
	sh.hist = sh.openHistory()
	// The completer needs the session, so the editor is built after the shell.
	// A nil store here is the shipped behavior: memory only, nothing on disk.
	var hs lineedit.History
	if sh.hist != nil {
		hs = sh.hist // avoid a non-nil interface wrapping a nil *Store
	}
	sh.ed = lineedit.New(stdin, stdout, sh.completeWord, hs)
	return sh
}

// openHistory opens the per-connection history file when -Y/--history is set.
// The tag defaults to the target, so each box keeps its own and a reconnect
// restores it; --history-tag overrides that.
func (sh *Shell) openHistory() *history.Store {
	if !sh.o.History {
		return nil
	}
	tag := sh.o.HistoryTag
	if tag == "" {
		tag = sh.o.IP
	}
	st, err := history.Open(tag)
	if err != nil {
		if !sh.json {
			fmt.Fprintln(sh.out, sh.c.Yellow("Warning: could not open command history: "+err.Error()))
		}
		return nil
	}
	return st
}

// completableVerbs are the built-ins offered when completing the first word.
// Loaded post-ex functions and -s script names are added dynamically; see
// verbCandidates.
var completableVerbs = []string{"bypass-4msi", "cls", "clear", "donut-loader", "download", "exit", "help", "invoke-binary", "menu", "quit", "services", "upload"}

// completeWord is the Tab handler. It never returns an error: a failed or slow
// completion yields no candidates rather than disturbing the prompt.
func (sh *Shell) completeWord(line string, pos int) (string, []string, string) {
	c := complete.Analyze(line, pos)
	var cands []string
	switch c.Target {
	case complete.TargetVerb:
		v := sh.verbCandidates()
		// Only reach for the target's ~1900 command names once something has
		// been typed. On an empty word Verbs returns every candidate, so
		// including them would answer a bare Tab with a wall of cmdlets instead
		// of the handful of built-ins that are actually useful there, and would
		// pay the fetch for a keystroke that told us nothing.
		if c.Word != "" {
			v = append(v, sh.remoteCommandNames()...)
		}
		cands = complete.Verbs(c.Word, v)
	case complete.TargetLocal:
		cands = complete.LocalPaths(c.Word)
	case complete.TargetExecutable:
		cands = sh.completeExecutable(c.Word)
	case complete.TargetOptions:
		cands = complete.Verbs(c.Word, c.Options)
	case complete.TargetPSNative:
		if sh.o.NoRPath { // -N/--no-rpath-completion
			return line[:pos], nil, line[pos:]
		}
		// PowerShell decides the replacement span itself here, so this returns
		// early with its head instead of the tokenizer's WordStart: at a
		// parameter or value site its parser is the authority on where the word
		// begins, and splicing at a different offset would corrupt the line.
		head, psCands := sh.psComplete(line, pos)
		if len(psCands) == 0 {
			return line[:pos], nil, line[pos:]
		}
		quotedPS := make([]string, 0, len(psCands))
		for _, x := range psCands {
			quotedPS = append(quotedPS, complete.Quote(x))
		}
		return line[:head], quotedPS, line[pos:]
	case complete.TargetRemote:
		if sh.o.NoRPath { // -N/--no-rpath-completion
			return line[:pos], nil, line[pos:]
		}
		cands = complete.RemotePaths(context.Background(), remoteLister{sh.s}, c.Word)
	default:
		return line[:pos], nil, line[pos:]
	}
	quoted := make([]string, 0, len(cands))
	for _, x := range cands {
		quoted = append(quoted, complete.Quote(x))
	}
	return line[:c.WordStart], quoted, line[pos:]
}

// remoteLister adapts a session to complete.RemoteLister, keeping the completion
// package free of any session dependency.
type remoteLister struct{ s *session.Session }

func (r remoteLister) ListDir(ctx context.Context, dir string) ([]complete.Entry, error) {
	target := dir
	if target == "" {
		target = "." // the shell's current location
	}
	// One line per entry, "1|name" for directories, so parsing stays trivial.
	script := fmt.Sprintf(
		`Get-ChildItem -LiteralPath %s -Force -ErrorAction SilentlyContinue | `+
			`ForEach-Object { "{0}|{1}" -f [int]$_.PSIsContainer,$_.Name }`, psQuote(target))
	res, err := r.s.RunRaw(ctx, script)
	if err != nil {
		return nil, err
	}
	var out []complete.Entry
	for _, v := range res.Output {
		for _, ln := range strings.Split(output.Text(v), "\n") {
			ln = strings.TrimSpace(ln)
			flag, name, ok := strings.Cut(ln, "|")
			if !ok || name == "" {
				continue
			}
			out = append(out, complete.Entry{Name: name, IsDir: flag == "1"})
		}
	}
	return out, nil
}

// psQuote renders a PowerShell single-quoted literal (doubling embedded quotes),
// so a path cannot break out and be evaluated.
func psQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

// isTerminal reports whether w is a character device, so a redirected or piped
// stdout never gets \r-animated progress written into it.
func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	st, err := f.Stat()
	if err != nil {
		return false
	}
	return st.Mode()&os.ModeCharDevice != 0
}

// notImplemented maps a recognized evil-winrm menu command to what it still
// needs. It is empty: every post-ex command upstream evil-winrm (v3.9) ships is
// now ported. The mechanism is kept because it is how `help` tells the truth
// about the port, and the next borrowed feature should land here first rather
// than failing silently. (There is no Dll-Loader in upstream.)
var notImplemented = map[string]string{}

func (sh *Shell) Run(ctx context.Context) error {
	// Ctrl-C cancels the running command instead of killing the session.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigs)

	if !sh.json {
		fmt.Fprintf(sh.out, "%s\n", sh.c.Bold("wsmancer shell "+cli.Version))
		fmt.Fprintf(sh.out, "%s %s\n", sh.c.Blue("Info:"), "type `help` for port status, `exit` to quit")
	}
	sh.startLog()
	defer sh.log.Close()
	sh.announceHistory()
	defer sh.hist.Close()
	sh.refreshCwd(ctx)

	defer sh.ed.Close()
	for {
		line, err := sh.ed.Prompt(sh.prompt())
		switch {
		case errors.Is(err, lineedit.ErrInterrupted):
			// Ctrl-C with nothing running: abandon the line, fresh prompt.
			continue
		case errors.Is(err, io.EOF):
			if sh.ed.Interactive() {
				fmt.Fprintln(sh.out)
			}
			return nil
		case err != nil:
			return err
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		sh.log.Event("PS %s> %s", sh.cwd, line)

		stop, err := sh.dispatch(ctx, sigs, line)
		if err != nil {
			sh.reportErr(line, err)
		}
		if stop {
			return nil
		}
	}
}

// startLog opens the session transcript when -l/--log is set. A logging failure
// is a warning, not fatal: an operator who asked for a log should hear that it
// isn't being written, but it should not abandon a live shell.
func (sh *Shell) startLog() {
	if !sh.o.Log {
		return
	}
	lg, err := transcript.Open(sh.o.IP)
	if err != nil {
		if !sh.json {
			fmt.Fprintln(sh.out, sh.c.Yellow("Warning: could not open session log: "+err.Error()))
		}
		return
	}
	sh.log = lg
	sh.log.Event("=== session start: %s (%s) ===", sh.o.IP, sh.s.AuthMode())
	if !sh.json {
		fmt.Fprintf(sh.out, "%s session log: %s\n", sh.c.Blue("Info:"), lg.Path())
	}
}

// dispatch handles built-ins, else sends the line to the remote runspace.
func (sh *Shell) dispatch(ctx context.Context, sigs <-chan os.Signal, line string) (stop bool, err error) {
	verb := strings.ToLower(strings.Fields(line)[0])
	switch verb {
	case "exit", "quit":
		return true, nil
	case "clear", "cls":
		if !sh.json {
			fmt.Fprint(sh.out, "\x1b[2J\x1b[H")
		}
		return false, nil
	case "help":
		sh.help()
		return false, nil
	case "upload", "download":
		return false, sh.transferCmd(ctx, sigs, verb, line)
	case "menu":
		return false, sh.menu(ctx)
	case "services":
		return false, sh.executeAs(ctx, sigs, servicesScript, "services")
	case "invoke-binary":
		return false, sh.invokeBinary(ctx, sigs, line)
	case "donut-loader":
		return false, sh.donutLoader(ctx, sigs, line)
	case "bypass-4msi":
		return false, sh.bypass4MSI(ctx, sigs)
	}
	// A bare "<name>.ps1" from the -s directory loads that script into the
	// runspace rather than running it as a remote command.
	if path, ok := sh.isScriptLoad(line); ok {
		return false, sh.loadScript(ctx, sigs, path)
	}
	if what, ok := notImplemented[verb]; ok {
		return false, fmt.Errorf("`%s` is not implemented yet in this port: %s", verb, what)
	}
	return false, sh.execute(ctx, sigs, line)
}

// transferCmd handles `upload <local> [remote]` and `download <remote> [local]`.
func (sh *Shell) transferCmd(ctx context.Context, sigs <-chan os.Signal, verb, line string) error {
	args := splitArgs(line)[1:]
	if len(args) == 0 || len(args) > 2 {
		if verb == "upload" {
			return errors.New(`usage: upload <local path> [remote path]   (quote paths containing spaces)`)
		}
		return errors.New(`usage: download <remote path> [local path]   (quote paths containing spaces)`)
	}
	src := args[0]
	var dst string
	if len(args) == 2 {
		dst = args[1]
	}

	// Ctrl-C aborts the transfer, not the session.
	cmdCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-sigs:
			cancel()
		case <-done:
		}
	}()

	prog, finish := sh.progress()
	start := time.Now()
	var err error
	if verb == "upload" {
		err = sh.tx.Upload(cmdCtx, src, dst, prog)
	} else {
		err = sh.tx.Download(cmdCtx, src, dst, prog)
	}
	moved := finish()
	if err != nil {
		return err
	}

	if sh.json {
		return sh.emitResult(output.JSONResult{
			Command:    line,
			Output:     []interface{}{map[string]interface{}{"action": verb, "source": src, "destination": dst, "bytes": moved}},
			DurationMS: time.Since(start).Milliseconds(),
		})
	}
	fmt.Fprintf(sh.out, "%s %s complete: %s (%s in %s)\n",
		sh.c.Blue("Info:"), verb, src, humanBytes(moved), time.Since(start).Round(time.Millisecond))
	dst2 := dst
	if dst2 == "" {
		dst2 = "(default)"
	}
	sh.log.Event("[%s] %s -> %s (%s)", verb, src, dst2, humanBytes(moved))
	return nil
}

// progress returns a callback for transfer progress and a finish function that
// clears the bar and reports the byte count. The bar is drawn only on a terminal
// in text mode; elsewhere it would corrupt piped output or a JSON stream.
func (sh *Shell) progress() (transfer.Progress, func() int64) {
	var last int64
	if sh.json || !sh.tty {
		return func(done, _ int64) { last = done }, func() int64 { return last }
	}
	var lastDraw time.Time
	return func(done, total int64) {
			last = done
			// Cap redraws; a fast local transfer would otherwise spend its time
			// writing escape codes.
			if time.Since(lastDraw) < 80*time.Millisecond && done != total {
				return
			}
			lastDraw = time.Now()
			fmt.Fprintf(sh.out, "\r\x1b[K  %s", progressBar(done, total))
		}, func() int64 {
			fmt.Fprint(sh.out, "\r\x1b[K")
			return last
		}
}

func progressBar(done, total int64) string {
	if total <= 0 {
		return fmt.Sprintf("%s transferred", humanBytes(done))
	}
	const width = 30
	frac := float64(done) / float64(total)
	if frac > 1 {
		frac = 1
	}
	filled := int(frac * width)
	return fmt.Sprintf("[%s%s] %5.1f%% %s / %s",
		strings.Repeat("=", filled), strings.Repeat(" ", width-filled),
		frac*100, humanBytes(done), humanBytes(total))
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	val := float64(n)
	for _, suffix := range []string{"KiB", "MiB", "GiB", "TiB"} {
		val /= unit
		if val < unit {
			return fmt.Sprintf("%.1f %s", val, suffix)
		}
	}
	return fmt.Sprintf("%.1f PiB", val/unit)
}

// splitArgs splits a command line into arguments, honouring single and double
// quotes so paths with spaces survive, `upload "C:\Program Files\x" y`.
//
// It delegates to the tokenizer the completer uses, so a path that Tab inserted
// is guaranteed to parse back to the same argument.
func splitArgs(line string) []string {
	toks := complete.Tokenize(line)
	if len(toks) == 0 {
		return nil
	}
	args := make([]string, 0, len(toks))
	for _, t := range toks {
		args = append(args, t.Text)
	}
	return args
}

// execute runs one remote command, with Ctrl-C wired to cancel just that command.
func (sh *Shell) execute(ctx context.Context, sigs <-chan os.Signal, line string) error {
	return sh.executeAs(ctx, sigs, line, line)
}

// executeAs runs the script `run` on the target but labels the result with
// `display`, for the JSON `command` field, the location-tracking check and any
// downstream use. A built-in like `services` runs a canned query yet reports
// itself by its friendly name.
func (sh *Shell) executeAs(ctx context.Context, sigs <-chan os.Signal, run, display string) error {
	cmdCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-sigs:
			fmt.Fprintln(sh.out, sh.c.Yellow("^C (canceling command)"))
			// Terminate the pipeline on the target before dropping the local
			// wait. Without this the command runs to completion up there and,
			// since the pool has one runspace, the next command queues behind
			// it and the shell looks hung.
			stopCtx, stopCancel := context.WithTimeout(context.Background(), 15*time.Second)
			if err := sh.s.StopPipelines(stopCtx); err != nil {
				fmt.Fprintln(sh.out, sh.c.Yellow("   (could not stop it remotely: "+sanitizeTerminal(err.Error())+")"))
			}
			stopCancel()
			cancel()
		case <-done:
		}
	}()

	start := time.Now()
	// text mode formats remotely for a console look; json mode keeps objects.
	runFn := sh.s.RunFormatted
	if sh.json {
		runFn = sh.s.RunRaw
	}
	res, err := runFn(cmdCtx, run)
	if err != nil {
		return err
	}
	// The command's own verdict, for Once's exit code. Assigned rather than
	// accumulated: it describes the last command, which for a one-shot is the
	// only one.
	sh.failed = res.HadErrors
	// If Ctrl-C canceled the command, its result is an aborted pipeline whose
	// only "output" is a context-canceled error record. Don't render that, the
	// "^C (canceling command)" line already told the operator what happened.
	if cmdCtx.Err() != nil {
		sh.failed = true
		return nil
	}
	// A dropped connection arrives the same way: not as a returned error, but as
	// an error *record* on an aborted pipeline (the fork's runPipelineReceive
	// calls pl.Fail with it). Rendered raw it is a four-layer wrap that buries
	// the point, so report it as the recoverable transport event it is.
	// A forgotten shell arrives the same way, and is checked first: it is the
	// narrower diagnosis, and reporting it as a mere dropped connection would
	// tell the operator to "run it again" against a shell that no longer exists.
	if err := resultShellForgotten(res); err != nil {
		sh.reportErr(display, err)
		return nil
	}
	if err := resultConnectionLost(res); err != nil {
		sh.reportErr(display, err)
		return nil
	}
	if sh.json {
		jr := output.NewJSONResult(display, res, time.Since(start))
		jr.ID = sh.reqID
		if sh.log != nil {
			var b strings.Builder
			_ = output.RenderJSON(&b, jr)
			sh.log.Output(b.String())
		}
		return sh.emitResult(jr)
	}
	output.RenderText(sh.out, res, sh.c)
	if sh.log != nil {
		// Log the same output without color, so the transcript is clean text.
		var b strings.Builder
		output.RenderText(&b, res, output.NewColors(false))
		sh.log.Output(b.String())
	}

	// The command may have changed directory; keep the prompt honest.
	if changesLocation(display) {
		sh.refreshCwd(ctx)
	}
	return nil
}

// changesLocation avoids paying a round trip for the prompt after every command,
// while still tracking cd/pushd/popd.
func changesLocation(line string) bool {
	switch strings.ToLower(strings.Fields(line)[0]) {
	case "cd", "chdir", "sl", "set-location", "pushd", "popd", "push-location", "pop-location":
		return true
	}
	return false
}

func (sh *Shell) refreshCwd(ctx context.Context) {
	pwdCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if p, err := sh.s.Pwd(pwdCtx); err == nil {
		sh.cwd = p
	}
}

func (sh *Shell) prompt() string {
	if sh.json {
		return "" // no prompt noise in a machine-readable stream
	}
	// Color is decided once, by output.Colors, the editor no longer has a say.
	// It used to: liner rejected a prompt containing a control rune and counted
	// each byte of an ANSI escape as a column, so under it the prompt had to be
	// plain. reeflective renders the escapes.
	return sh.c.Blue("PS ") + sh.cwd + "> "
}

func (sh *Shell) reportErr(cmd string, err error) {
	if errors.Is(err, context.Canceled) {
		return
	}
	sh.failed = true
	// The transcript always gets the full error; only the terminal rendering is
	// simplified below, so nothing is lost for debugging.
	sh.log.Event("Error: %s", err.Error())
	// Checked before the json branch, and before connectionLost, because a
	// forgotten shell needs *acting on* and not merely reporting: without a new
	// shell every later command fails the same way. It is also the narrower
	// case, see shellForgotten on why it is not just another connection loss.
	//
	// Not in one-shot, though: there is no next command to protect, the failed
	// one is never re-run, and a fresh shell would cost a round trip only to
	// announce state that the exiting process cannot use, "a new shell has been
	// opened" would be true and useless. -x reports it like any other error and
	// exits non-zero, leaving the caller to decide whether to run again.
	if shellForgotten(err) && !sh.once {
		// In json mode the failed command is reported as an error record first,
		// then recoverShell adds a structured `event` on the same stream. Both
		// land on sh.out so a batch consumer reading only stdout sees the whole
		// story: this command failed, and a new shell was opened with state lost.
		if sh.json {
			_ = sh.emitError(cmd, err)
		}
		sh.recoverShell()
		return
	}
	if sh.json {
		_ = sh.emitError(cmd, err)
		return
	}
	if connectionLost(err) {
		fmt.Fprintln(sh.out, sh.c.Red("Error: connection to the target dropped; this command was lost."))
		fmt.Fprintln(sh.out, sh.c.Yellow("   The session reconnects automatically, run it again."))
		return
	}
	fmt.Fprintln(sh.out, sh.c.Red("Error: "+sanitizeTerminal(err.Error())))
}

// resultConnectionLost returns the connection-loss error carried in a result's
// error stream, or nil. A lost connection aborts the pipeline, so the failure
// surfaces as an error record rather than a returned error.
//
// It deliberately only inspects a result that produced no output: a command that
// streamed output and then hit a genuine PowerShell error must still render
// normally, and only an aborted-before-anything pipeline is unambiguously the
// transport dying.
func resultConnectionLost(res *client.Result) error {
	if res == nil || len(res.Output) > 0 || len(res.Errors) == 0 {
		return nil
	}
	for _, e := range res.Errors {
		if err, ok := e.(error); ok && connectionLost(err) {
			return err
		}
		if s, ok := e.(string); ok && connectionLost(errors.New(s)) {
			return errors.New(s)
		}
	}
	return nil
}

// connectionLost reports whether err is the transport losing its connection,
// rather than anything the command itself did wrong.
//
// Worth special-casing because the raw error is a four-layer wrapping,
// "read fragment header: wsman receive: receive: transport: request failed: Post
// ...: i/o timeout (Client.Timeout exceeded while awaiting headers)", that
// buries the one fact the operator needs. A dropped connection is *recoverable*:
// the sealing transport re-dials on the next request and WinRM re-attaches the
// existing shell, so the runspace (variables, functions, working directory,
// anything loaded with -s) survives and only the in-flight command is lost.
// Verified against a live box by severing the TCP connection mid-command.
//
// Matching is by sentinel first and text second: the fork wraps some transport
// failures with %w (so errors.Is reaches the syscall) but stringifies others,
// and net/url's timeout wrapper is only reachable via the net.Error interface.
func connectionLost(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) ||
		errors.Is(err, syscall.ECONNABORTED) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	s := err.Error()
	for _, frag := range []string{
		"connection reset by peer",
		"broken pipe",
		"use of closed network connection",
		"i/o timeout",
		"unexpected EOF",
	} {
		if strings.Contains(s, frag) {
			return true
		}
	}
	return false
}

// sanitizeTerminal makes an arbitrary string safe to print to a terminal. Error
// values can carry attacker- or transport-influenced bytes, most sharply, a
// failed WSMan request surfaces the raw HTTP body, which on a sealed connection
// is encrypted ciphertext. Printed verbatim those bytes are read as ESC/cursor
// sequences and scramble the display. Here newlines and tabs pass through, every
// printable rune is kept, and any run of control/binary/invalid-UTF-8 runes
// collapses to a single "." so the message stays readable and bounded.
func sanitizeTerminal(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	collapsed := false
	for _, r := range s {
		if r != utf8.RuneError && (r == '\n' || r == '\t' || unicode.IsGraphic(r)) {
			b.WriteRune(r)
			collapsed = false
			continue
		}
		if !collapsed {
			b.WriteByte('.')
			collapsed = true
		}
	}
	return b.String()
}

func (sh *Shell) help() {
	if sh.json {
		return
	}
	fmt.Fprintf(sh.out, `
Any PowerShell command is sent to the remote runspace.

Working now:
  upload <local> [remote]   copy a file or directory to the target
  download <remote> [local] copy a file or directory from the target
  invoke-binary <exe> [a,b] run a local .NET assembly in memory (args comma-separated;
                            a bare name resolves against -e/--executables)
  donut-loader -process_id <pid> -donutfile <local .bin>
                            inject local donut shellcode into a remote process (x64 only)
  bypass-4msi               patch AmsiScanBuffer in this runspace (noisy; do it last)
  <name>.ps1            load that script from the -s directory into the session
  menu                  list the functions loaded from your scripts
  services              list non-system services, paths, and your access (privesc recon)
  help                  this message
  clear, cls            clear the screen
  exit, quit            close the session

Line editing (on a terminal):
  Up/Down or Ctrl-P/N  command history        Tab      complete paths
  Ctrl-A / Ctrl-E      start / end of line    Ctrl-R   search history
  Right or Ctrl-E      accept the inline suggestion (ghost text, default editor)
  Ctrl-W / Ctrl-U      delete word / line     Ctrl-L   clear screen
  Ctrl-C               cancel the running command, or clear the line if idle
  Ctrl-D               exit
`)
	// Only shown when there is something to confess. An empty "not implemented"
	// heading reads like a truncated help page.
	if len(notImplemented) > 0 {
		fmt.Fprintln(sh.out, "Not implemented yet in this port:")
		stubs := make([]string, 0, len(notImplemented))
		for k := range notImplemented {
			stubs = append(stubs, k)
		}
		sort.Strings(stubs)
		for _, k := range stubs {
			fmt.Fprintf(sh.out, "  %-22s%s\n", k, notImplemented[k])
		}
	}
	fmt.Fprintln(sh.out)
}

// announceHistory tells the operator that commands are being written to disk and
// how to keep one out. Saying it every session is deliberate: this reverses the
// tool's default posture, and a persisted history is exactly the sort of thing
// that should never be quietly on.
func (sh *Shell) announceHistory() {
	if sh.hist == nil || sh.json {
		return
	}
	fmt.Fprintf(sh.out, "%s command history: %s %s\n", sh.c.Blue("Info:"), sh.hist.Path(),
		sh.c.Yellow("(on disk, prefix a command with a space to keep it out)"))
}
