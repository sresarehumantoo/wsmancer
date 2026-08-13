package shell

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/sresarehumantoo/wsmancer/internal/cli"
	"github.com/sresarehumantoo/wsmancer/internal/output"
	"github.com/sresarehumantoo/wsmancer/internal/session"
	"github.com/sresarehumantoo/wsmancer/internal/transcript"
)

// NewBatch builds a Shell for batch mode (`-x -`): commands are read from a
// stream and run through the same dispatch as the REPL, over one connection.
//
// It is the multi-command sibling of NewOnce, and the difference from it is
// deliberate. once stays false, because batch is a *session*: there is a next
// command to protect, so a forgotten shell is recovered onto and the run
// continues, rather than being merely reported and abandoned. Like NewOnce it
// leaves sh.ed and sh.hist nil, Batch reads the stream itself and a prompt
// history has no reader, so Batch must reach nothing that touches them.
func NewBatch(s *session.Session, o *cli.Options, stdout io.Writer) *Shell {
	return newShell(s, o, stdout)
}

// Batch reads commands from r, one per line, and runs each through the shell's
// own dispatch over a single session, the streaming form of -x. It returns the
// process exit code: 0 if every command succeeded, 1 if any failed.
//
// This is the reason the port claims to beat "nxc-adhoc clunkiness": an agent or
// a script drives a whole session over one authenticated connection, so the
// runspace state (working directory, variables, functions, -s scripts,
// in-memory assemblies) persists across commands, and each command's structured
// result streams out as it completes, one NDJSON object per line under -o json.
//
// It shares dispatch with the REPL and the one-shot, so a built-in behaves
// identically in all three; the only things batch owns are the aggregate exit
// code and the stream-reading loop. A blank line is skipped, and `exit`/`quit`
// ends the batch early (dispatch's stop), matching the interactive shell.
func (sh *Shell) Batch(ctx context.Context, r io.Reader) int {
	// Ctrl-C terminates the running command's remote pipeline, exactly as in the
	// REPL and the one-shot, the session survives so the next line still runs.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigs)

	sh.startBatchLog()
	defer sh.log.Close()

	// Same 1 MiB line cap as the piped plainEditor, so a long one-liner (a
	// base64 blob pasted as a command) reads the same way in both paths.
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	anyFailed := false
	for sc.Scan() {
		raw := strings.TrimSpace(sc.Text())
		if raw == "" {
			continue
		}
		// A line may be a JSON request object {"id":..., "command":"..."} for
		// correlation, or a bare command line. parseRequest tells them apart and
		// hands back the command to run plus the id to echo on every object it
		// produces; reqID is cleared after so a bare line that follows a request
		// carries no id.
		line, id := parseRequest(raw)
		sh.reqID = id
		sh.log.Event("PS %s> %s", sh.cwd, line)

		// failed describes the last command; reset before each so one failure
		// does not leak its verdict onto the next line's success.
		sh.failed = false
		stop, err := sh.dispatch(ctx, sigs, line)
		if err != nil {
			sh.reportErr(line, err)
		}
		sh.reqID = nil
		if sh.failed {
			anyFailed = true
		}
		if stop {
			break
		}
	}
	if err := sc.Err(); err != nil {
		// A read error on the command stream is not a command failure, but the
		// caller should still hear it and get a non-zero code.
		if sh.json {
			_ = output.RenderEvent(sh.out, "input_error", "reading commands: "+err.Error(), false)
		} else {
			fmt.Fprintln(os.Stderr, sh.c.Red("Error: reading commands: "+err.Error()))
		}
		return 1
	}
	if anyFailed {
		return 1
	}
	return 0
}

// parseRequest interprets one batch input line. It returns the command to run
// and the correlation id to echo on the response.
//
// A line is a structured request only when it is a JSON object with a non-empty
// string "command", then its "id" (any JSON value) is the correlation token.
// Anything else is a bare command line run verbatim with no id: a line that does
// not start with "{", one that is not valid JSON (a PowerShell scriptblock
// `{ ... }` is not), or a JSON object without a usable command. This keeps
// bare-line batch working unchanged while letting an agent opt into correlation
// per line, and the "{" + valid-JSON + string-command test is strict enough that
// an ordinary command is never mistaken for a request.
func parseRequest(raw string) (command string, id interface{}) {
	if !strings.HasPrefix(raw, "{") {
		return raw, nil
	}
	var r struct {
		ID      interface{} `json:"id"`
		Command string      `json:"command"`
	}
	if err := json.Unmarshal([]byte(raw), &r); err != nil || r.Command == "" {
		return raw, nil
	}
	return r.Command, r.ID
}

// startBatchLog opens the -l transcript for a batch session. Like startOnceLog
// it omits the "session log: <path>" line that belongs on a prompt, not in a
// stream a consumer is about to parse; the per-command lines are written by the
// loop.
func (sh *Shell) startBatchLog() {
	if !sh.o.Log {
		return
	}
	lg, err := transcript.Open(sh.o.IP)
	if err != nil {
		if !sh.json {
			fmt.Fprintln(os.Stderr, sh.c.Yellow("Warning: could not open session log: "+err.Error()))
		}
		return
	}
	sh.log = lg
	sh.log.Event("=== batch session: %s (%s) ===", sh.o.IP, sh.s.AuthMode())
}
