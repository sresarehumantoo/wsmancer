package psutil

import "strings"

// Quote renders a Go string as a PowerShell single-quoted literal, where the
// only escape is a doubled quote. Single quotes prevent PowerShell from
// expanding $(...) or variables inside a path we do not control.
func Quote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}
