package psutil

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// Quote renders a Go string as a PowerShell single-quoted literal, where the
// only escape is a doubled quote. Single quotes prevent PowerShell from
// expanding $(...) or variables inside a path we do not control.
func Quote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

// ParseNTHash accepts a bare 32-hex NT hash, the LM:NT form pasted from
// secretsdump output, or an empty string (returns nil, nil).
func ParseNTHash(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	if i := strings.LastIndex(s, ":"); i >= 0 {
		s = s[i+1:]
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("NT hash is not valid hex: %w", err)
	}
	if len(b) != 16 {
		return nil, fmt.Errorf("NT hash must be a 16-byte value (32 hex chars), got %d", len(b))
	}
	return b, nil
}
