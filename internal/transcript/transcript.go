// Package transcript writes a timestamped record of a session to a file, the
// -l/--log feature. It mirrors the original evil-winrm: a per-session, per-host
// transcript under ~/.wsmancer/logs (override with $WSMANCER_LOG_DIR), so an
// operator keeps a paper trail of exactly what was run and what came back.
//
// Every method is safe to call on a nil *Log, so a caller can hold a
// possibly-nil handle and log unconditionally without guarding each call.
package transcript

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const stamp = "2006-01-02 15:04:05"

type Log struct {
	mu   sync.Mutex
	f    *os.File
	path string
}

// Open creates a new transcript file for host and returns it. The path is
// <root>/<host>/<YYYYMMDD-HHMMSS>.log, where root is $WSMANCER_LOG_DIR or
// ~/.wsmancer/logs. The directory tree is created if missing.
func Open(host string) (*Log, error) {
	root, err := logRoot()
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(root, sanitizeHost(host))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, time.Now().Format("20060102-150405")+".log")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	return &Log{f: f, path: path}, nil
}

// Path is the file being written, for an "Info: session log: ..." message.
func (l *Log) Path() string {
	if l == nil {
		return ""
	}
	return l.path
}

// Event writes one timestamped line, a command, a transfer, an error.
func (l *Log) Event(format string, args ...any) {
	if l == nil {
		return
	}
	l.write(time.Now().Format(stamp) + "  " + fmt.Sprintf(format, args...))
}

// Output writes a raw block, such as a command's output, with no per-line
// timestamp so it reads exactly as it did on screen. Trailing blank lines and
// empty blocks are dropped.
func (l *Log) Output(text string) {
	if l == nil {
		return
	}
	text = strings.TrimRight(text, "\n")
	if text == "" {
		return
	}
	l.write(text)
}

// Close writes an end marker and closes the file.
func (l *Log) Close() error {
	if l == nil {
		return nil
	}
	l.Event("=== session end ===")
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.f.Close()
}

func (l *Log) write(s string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintln(l.f, s)
}

func logRoot() (string, error) {
	if d := os.Getenv("WSMANCER_LOG_DIR"); d != "" {
		return d, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".wsmancer", "logs"), nil
}

// sanitizeHost keeps a host usable as a single path element: a hostile or odd
// target name must not be able to introduce path separators or traversal.
func sanitizeHost(host string) string {
	if host == "" {
		return "unknown"
	}
	clean := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			return r
		case r == '.' || r == '-' || r == '_':
			return r
		default:
			return '_'
		}
	}, host)
	// Guard against a name that reduces to dots ("." / "..").
	if strings.Trim(clean, ".") == "" {
		return "unknown"
	}
	return clean
}
