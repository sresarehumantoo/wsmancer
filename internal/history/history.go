// Package history is an opt-in, on-disk command history, tagged per connection
// so a reconnect to the same box picks up where the last session left off.
//
// It deliberately reverses this tool's default posture. Without -Y/--history the
// shell keeps history in memory only, because a session's commands routinely
// contain hashes, passwords and target names.
// Turning it on writes those to disk, so: the flag is opt-in, the shell says so
// on connect, the file is 0600 under a 0700 directory, and a command prefixed
// with a space is never recorded, the ignorespace escape hatch every shell has,
// for exactly the one-off `net user … P@ssw0rd` this tool exists to run.
//
// Every method is safe to call on a nil *Store, so a caller can hold a
// possibly-nil handle and record unconditionally, matching internal/transcript.
package history

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Store is a file-backed command history. It satisfies reeflective/readline's
// History interface structurally (Write/GetLine/Len/Dump), that type is an
// alias for an interface, so no adapter is needed and this package never has to
// import the editor.
type Store struct {
	mu    sync.Mutex
	path  string
	lines []string
	f     *os.File
}

// Open loads the history for tag, creating the file if needed. The tag names the
// connection, the host by default, so several boxes keep separate histories
// and reconnecting to one restores its own.
func Open(tag string) (*Store, error) {
	root, err := historyRoot()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, err
	}
	path := filepath.Join(root, SanitizeTag(tag)+".hist")
	lines, err := load(path)
	if err != nil {
		return nil, err
	}
	// Kept open for the session: a history line should reach disk as soon as it
	// is run, so a session that dies to a dropped VPN or a kill still leaves the
	// commands behind. Reopening per write would be the only alternative that
	// survives, and it costs a syscall per keystroke-accepted line.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	return &Store{path: path, lines: lines, f: f}, nil
}

// load reads an existing history file. A missing file is not an error, that is
// simply the first connection to this target.
func load(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		if s := sc.Text(); s != "" {
			lines = append(lines, s)
		}
	}
	return lines, sc.Err()
}

func (s *Store) Path() string {
	if s == nil {
		return ""
	}
	return s.path
}

// Write records a line, and is also the method reeflective calls for every
// accepted line. All the filtering lives here rather than in the callers,
// because under reeflective the library, not the shell, decides when a line is
// accepted, so a filter anywhere else would apply to only one of the two editors.
//
// The return value is the resulting line count, per the editor's interface.
func (s *Store) Write(line string) (int, error) {
	if s == nil {
		return 0, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !Recordable(line) {
		return len(s.lines), nil
	}
	trimmed := strings.TrimSpace(line)
	// Consecutive duplicates are noise in a history file, and a repeated command
	// is exactly what Up-arrow is for.
	if len(s.lines) > 0 && s.lines[len(s.lines)-1] == trimmed {
		return len(s.lines), nil
	}
	s.lines = append(s.lines, trimmed)
	if s.f != nil {
		if _, err := s.f.WriteString(trimmed + "\n"); err != nil {
			return len(s.lines), err
		}
	}
	return len(s.lines), nil
}

// Recordable reports whether a line should be persisted. A line starting with
// whitespace is skipped, the ignorespace convention, which is the operator's
// per-command opt-out for anything they would rather not leave on disk.
//
// It takes the *raw* line: the shell trims before dispatching, so a caller that
// records the trimmed form has already destroyed the only signal this reads.
func Recordable(line string) bool {
	if strings.TrimSpace(line) == "" {
		return false
	}
	return !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t")
}

// GetLine returns the line at pos, oldest first (the editor's interface).
func (s *Store) GetLine(pos int) (string, error) {
	if s == nil {
		return "", nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if pos < 0 || pos >= len(s.lines) {
		return "", nil
	}
	return s.lines[pos], nil
}

func (s *Store) Len() int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.lines)
}

// Dump satisfies the editor's interface; it is unused by the library.
func (s *Store) Dump() interface{} {
	if s == nil {
		return nil
	}
	return s.Lines()
}

// Lines returns a copy of the history, oldest first, a copy, so no caller can
// alias the slice this Store keeps appending to.
func (s *Store) Lines() []string {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.lines))
	copy(out, s.lines)
	return out
}

func (s *Store) Close() error {
	if s == nil || s.f == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	err := s.f.Close()
	s.f = nil
	return err
}

// historyRoot is where per-connection history files live. $WSMANCER_HISTORY_DIR
// overrides it, mirroring $WSMANCER_LOG_DIR for transcripts.
func historyRoot() (string, error) {
	if d := os.Getenv("WSMANCER_HISTORY_DIR"); d != "" {
		return d, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".wsmancer", "history"), nil
}

// SanitizeTag makes a connection tag safe to use as a filename. A tag can come
// from an operator-supplied --history-tag or from the target's own hostname, so
// it must never escape the history directory.
func SanitizeTag(tag string) string {
	clean := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			return r
		case r == '.' || r == '_' || r == '-' || r == '@':
			return r
		default:
			return '_'
		}
	}, tag)
	// A name of only dots would be "." or "..", a directory, not a file.
	if strings.Trim(clean, ".") == "" {
		return "unknown"
	}
	return clean
}
