package shell

import (
	"reflect"
	"testing"
)

func TestSplitArgsHandlesQuotedPaths(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{`upload a.txt`, []string{"upload", "a.txt"}},
		{`upload a.txt C:\tmp\a.txt`, []string{"upload", "a.txt", `C:\tmp\a.txt`}},
		{`upload "local file.txt" "C:\Program Files\x.txt"`,
			[]string{"upload", "local file.txt", `C:\Program Files\x.txt`}},
		// Adjacent quoted sections with no space between them concatenate into
		// one argument, as a POSIX shell does.
		{`download 'C:\it''s here\x'`, []string{"download", `C:\its here\x`}},
		{`upload pre"quoted"post`, []string{"upload", "prequotedpost"}},
		{"upload    spaced\t\tout", []string{"upload", "spaced", "out"}},
		{`download "" x`, []string{"download", "", "x"}},
		{"  ", nil},
	}
	for _, c := range cases {
		if got := splitArgs(c.in); !reflect.DeepEqual(got, c.want) {
			t.Errorf("splitArgs(%q) = %#v, want %#v", c.in, got, c.want)
		}
	}
}

func TestHumanBytes(t *testing.T) {
	cases := map[int64]string{
		0:            "0 B",
		512:          "512 B",
		1024:         "1.0 KiB",
		1536:         "1.5 KiB",
		1048576:      "1.0 MiB",
		10 * 1 << 20: "10.0 MiB",
	}
	for in, want := range cases {
		if got := humanBytes(in); got != want {
			t.Errorf("humanBytes(%d) = %q, want %q", in, got, want)
		}
	}
}

// A zero or unknown total must not divide by zero or print a nonsense percentage.
func TestProgressBarUnknownTotal(t *testing.T) {
	if got := progressBar(2048, -1); got != "2.0 KiB transferred" {
		t.Errorf("progressBar with unknown total = %q", got)
	}
	if got := progressBar(0, 0); got != "0 B transferred" {
		t.Errorf("progressBar(0,0) = %q", got)
	}
}
