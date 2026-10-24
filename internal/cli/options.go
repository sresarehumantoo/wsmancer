// Package cli parses the command line. The flag surface intentionally mirrors
// Ruby evil-winrm's (short and long form for each option) so muscle memory and
// existing scripts carry over, plus a few additions this port needs:
// -x/--command for one-shot execution, -o/--output for structured output, and
// --skew for labs whose DC clock is minutes off.
package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/sresarehumantoo/wsmancer/internal/proxydial"
)

// Version is the build version. It defaults to the release it was cut for and
// is overridden at release time via -ldflags (see .goreleaser.yml), so GoReleaser
// binaries always carry the exact tag while `go install` reports this default.
var Version = "0.1.2"

type Options struct {
	// connection
	IP        string
	Port      int
	URL       string
	SSL       bool
	UserAgent string

	// Proxy routes the connection through a SOCKS5 proxy, for a listener that is
	// only reachable from inside the target network. proxychains cannot do this
	// job for a static Go binary, see internal/proxydial.
	Proxy string

	// auth
	User      string
	Password  string
	Hash      string // NT hash for pass-the-hash
	Realm     string // Kerberos realm; also the NTLM domain
	CCache    string // Kerberos ticket file (ccache or kirbi; -K keeps its name)
	SPNPrefix string
	Skew      int // seconds to add to the AP-REQ authenticator

	// TLS client cert
	PubKey  string
	PrivKey string

	// TLS server verification (HTTPS / -S only)
	CACert            string // --ca-cert: PEM CA bundle to verify the target against
	AcceptFingerprint string // --accept-fingerprint: pin the target cert by SHA-256
	Insecure          bool   // --insecure: skip verification (MITM-vulnerable)

	// local resource dirs
	Scripts     string
	Executables string

	// behavior
	Command  string // one-shot; empty means interactive
	Output   string // "text" or "json"
	ChunkKB  int    // transfer chunk size; see --chunk-size
	NoColors bool
	NoRPath  bool
	Log      bool

	// History opts into an on-disk, per-connection command history. Off by
	// default: a session's commands routinely carry hashes and passwords, so
	// persisting them is the operator's call, never the tool's. HistoryTag names
	// the file; empty means derive it from the target.
	History    bool
	HistoryTag string

	Version bool
	Help    bool
}

// AuthMode is how we will authenticate, derived from which creds were supplied.
type AuthMode int

const (
	AuthPassword    AuthMode = iota // NTLM with a password
	AuthHash                        // NTLM pass-the-hash
	AuthKerberos                    // Kerberos from a ticket file (ccache or kirbi)
	AuthCertificate                 // the TLS client certificate IS the credential
)

// AuthMode picks the mode from the credentials supplied.
//
// -c/-k are deliberately *not* enough on their own to mean "certificate
// authentication" here, they mean it only when nothing else was given. Ruby
// evil-winrm treats a certificate as the credential unconditionally and ignores
// any -u/-p alongside it; this port already supported presenting a client
// certificate *with* NTLM/Kerberos (mutual TLS plus a real handshake), which is
// the stronger arrangement and one upstream cannot express. Matching upstream
// exactly would have silently deleted it. So: credentials present ⇒ that mode,
// certificate along for the TLS handshake; no credentials ⇒ the certificate is
// the credential.
func (o *Options) AuthMode() AuthMode {
	switch {
	case o.CCache != "":
		return AuthKerberos
	case o.Hash != "":
		return AuthHash
	case o.Password == "" && o.PubKey != "" && o.PrivKey != "":
		return AuthCertificate
	default:
		return AuthPassword
	}
}

// NeedsPassword reports whether the only thing missing is the password: an NTLM
// login with no -p, no -H and no -K. The caller may then prompt for one (see
// cmd/wsmancer), which is the one credential a tool may ask for, a hash, a
// ticket or a certificate is a file, not something anyone types.
//
// Certificate auth is excluded by construction: AuthMode returns
// AuthCertificate exactly when a certificate was given and no password, so a
// cert login can never be stopped to ask for a password nobody has.
func (o *Options) NeedsPassword() bool {
	return o.AuthMode() == AuthPassword && o.Password == ""
}

// Endpoint builds the WinRM URL. Port defaults follow the scheme.
func (o *Options) Endpoint() string {
	scheme := "http"
	if o.SSL {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s:%d%s", scheme, o.IP, o.Port, o.URL)
}

func Parse(argv []string, stderr io.Writer) (*Options, error) {
	o := &Options{}
	fs := flag.NewFlagSet("wsmancer", flag.ContinueOnError)
	fs.SetOutput(io.Discard) // we print our own usage
	fs.Usage = func() {}

	// Go's flag package treats -x and --x identically, so registering both the
	// short and long name against the same target gives us getopt-ish behavior.
	str := func(p *string, def string, short, long string) {
		fs.StringVar(p, short, def, "")
		fs.StringVar(p, long, def, "")
	}
	boolean := func(p *bool, short, long string) {
		fs.BoolVar(p, short, false, "")
		fs.BoolVar(p, long, false, "")
	}

	str(&o.IP, "", "i", "ip")
	str(&o.User, "", "u", "user")
	str(&o.Password, "", "p", "password")
	str(&o.Hash, "", "H", "hash")
	str(&o.Realm, "", "r", "realm")
	str(&o.CCache, "", "K", "ccache")
	str(&o.URL, "/wsman", "U", "url")
	str(&o.UserAgent, "Microsoft WinRM Client", "a", "user-agent")
	str(&o.PubKey, "", "c", "pub-key")
	str(&o.PrivKey, "", "k", "priv-key")
	str(&o.Scripts, "", "s", "scripts")
	str(&o.Executables, "", "e", "executables")
	str(&o.Command, "", "x", "command")
	str(&o.Output, "text", "o", "output")
	boolean(&o.SSL, "S", "ssl")
	boolean(&o.NoColors, "n", "no-colors")
	boolean(&o.NoRPath, "N", "no-rpath-completion")
	boolean(&o.Log, "l", "log")
	boolean(&o.History, "Y", "history")
	// Long-form only: registering "" as a short name would define a nameless flag.
	fs.StringVar(&o.HistoryTag, "history-tag", "", "")
	boolean(&o.Version, "V", "version")
	boolean(&o.Help, "h", "help")

	// TLS server verification: long-form only (short letters are all taken, and
	// ligolo-ng, whose fingerprint model this mirrors, uses long names too).
	// Long-form only, like the TLS flags: every short letter is taken, and
	// --proxy is what curl, ligolo-ng and friends call it.
	fs.StringVar(&o.Proxy, "proxy", "", "")

	fs.StringVar(&o.CACert, "ca-cert", "", "")
	fs.StringVar(&o.AcceptFingerprint, "accept-fingerprint", "", "")
	fs.BoolVar(&o.Insecure, "insecure", false, "")

	// port: 0 means "not given", so the SSL default can apply afterwards
	port := fs.Int("P", 0, "")
	fs.IntVar(port, "port", 0, "")
	fs.StringVar(&o.SPNPrefix, "spn", "HTTP", "")
	fs.IntVar(&o.Skew, "skew", 0, "")
	fs.IntVar(&o.ChunkKB, "chunk-size", 192, "")

	if err := fs.Parse(argv); err != nil {
		return nil, fmt.Errorf("%w\n\nrun with --help for usage", err)
	}
	if o.Help || o.Version {
		return o, nil
	}

	if *port != 0 {
		o.Port = *port
	} else if o.SSL {
		o.Port = 5986
	} else {
		o.Port = 5985
	}
	if !strings.HasPrefix(o.URL, "/") {
		o.URL = "/" + o.URL
	}
	// A password on the command line is visible in ps output, so the env var and
	// the terminal prompt (see NeedsPassword, and cmd/wsmancer) are the safer
	// ways in.
	if o.Password == "" {
		o.Password = os.Getenv("WSMANCER_PASSWORD")
	}
	// A proxy URL can carry credentials, and it is the same for every target on
	// an engagement, both reasons to let it come from the environment.
	if o.Proxy == "" {
		o.Proxy = os.Getenv("WSMANCER_PROXY")
	}
	return o, o.validate()
}

func (o *Options) validate() error {
	if o.IP == "" {
		return errors.New("-i/--ip is required")
	}
	switch o.Output {
	case "text", "json":
	default:
		return fmt.Errorf("-o/--output must be text or json, got %q", o.Output)
	}
	switch o.AuthMode() {
	case AuthKerberos, AuthCertificate:
		// Neither names a user on the wire: the ticket carries the principal, and
		// a certificate is mapped to an account by the target itself.
	default:
		if o.User == "" {
			return errors.New("-u/--user is required unless authenticating with a Kerberos ticket (-K) " +
				"or a client certificate (-c/-k with no password)")
		}
	}
	// Parse the proxy URL now so a typo fails at startup with a usable message,
	// rather than as a dial error against the first request. This builds a
	// dialer and throws it away; it performs no I/O.
	if _, err := proxydial.New(o.Proxy); err != nil {
		return err
	}
	if o.ChunkKB < 1 || o.ChunkKB > 4096 {
		return fmt.Errorf("--chunk-size must be between 1 and 4096 KB, got %d", o.ChunkKB)
	}
	if o.Hash != "" && o.Password != "" {
		return errors.New("-H/--hash and -p/--password are mutually exclusive")
	}
	if (o.PubKey == "") != (o.PrivKey == "") {
		return errors.New("-c/--pub-key and -k/--priv-key must be given together")
	}
	if o.PubKey != "" {
		if !o.SSL {
			return errors.New("-c/-k client certificates are presented during the TLS handshake; add -S/--ssl")
		}
		for _, f := range []struct{ path, flag string }{
			{o.PubKey, "-c/--pub-key"}, {o.PrivKey, "-k/--priv-key"},
		} {
			if _, err := os.Stat(f.path); err != nil {
				return fmt.Errorf("%s: %w", f.flag, err)
			}
		}
	}
	// TLS server verification: at most one mode, and only over HTTPS.
	nTLS := 0
	for _, set := range []bool{o.Insecure, o.CACert != "", o.AcceptFingerprint != ""} {
		if set {
			nTLS++
		}
	}
	if nTLS > 1 {
		return errors.New("--insecure, --ca-cert and --accept-fingerprint are mutually exclusive")
	}
	if nTLS == 1 && !o.SSL {
		return errors.New("--insecure/--ca-cert/--accept-fingerprint apply to the TLS connection; add -S/--ssl")
	}
	if o.AcceptFingerprint != "" {
		if _, err := NormalizeFingerprint(o.AcceptFingerprint); err != nil {
			return fmt.Errorf("--accept-fingerprint: %w", err)
		}
	}
	if o.CACert != "" {
		if st, err := os.Stat(o.CACert); err != nil {
			return fmt.Errorf("--ca-cert: %w", err)
		} else if st.IsDir() {
			return fmt.Errorf("--ca-cert: %s is a directory", o.CACert)
		}
	}
	for _, d := range []struct{ path, what string }{
		{o.Scripts, "-s/--scripts"},
		{o.Executables, "-e/--executables"},
	} {
		if d.path == "" {
			continue
		}
		st, err := os.Stat(d.path)
		if err != nil {
			return fmt.Errorf("%s: %w", d.what, err)
		}
		if !st.IsDir() {
			return fmt.Errorf("%s: %s is not a directory", d.what, d.path)
		}
	}
	return nil
}

// NormalizeFingerprint parses a SHA-256 certificate fingerprint given in hex,
// tolerant of the colons, spaces and case that copy-pasted fingerprints carry
// (`AA:BB:..` or `aabb..`), and returns the 32 raw bytes.
func NormalizeFingerprint(s string) ([]byte, error) {
	clean := strings.Map(func(r rune) rune {
		switch r {
		case ':', ' ', '\t', '\n', '\r', '-':
			return -1
		}
		return r
	}, s)
	b, err := hex.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("not valid hex: %v", err)
	}
	if len(b) != sha256.Size {
		return nil, fmt.Errorf("must be a SHA-256 hash (%d bytes / %d hex chars), got %d bytes",
			sha256.Size, sha256.Size*2, len(b))
	}
	return b, nil
}

// FormatFingerprint renders a fingerprint as lowercase colon-separated hex, the
// form shown in error messages so it can be pasted straight back into
// --accept-fingerprint.
func FormatFingerprint(b []byte) string {
	const hexd = "0123456789abcdef"
	buf := make([]byte, 0, len(b)*3)
	for i, x := range b {
		if i > 0 {
			buf = append(buf, ':')
		}
		buf = append(buf, hexd[x>>4], hexd[x&0x0f])
	}
	return string(buf)
}

var usage = `wsmancer ` + Version + `, WinRM shell for pentesting

Usage: wsmancer -i <target> [-u <user>] [-p <pass> | -H <nthash> | -K <ticket>] [options]

Connection:
  -i, --ip IP                 target IP or hostname (FQDN for Kerberos) (required)
  -P, --port PORT             port (default 5985, or 5986 with --ssl)
  -U, --url URL               endpoint path (default /wsman)
  -S, --ssl                   use HTTPS
  -a, --user-agent UA         User-Agent (default "Microsoft WinRM Client")
  -c, --pub-key PATH          client certificate (needs -S; with -k). With no
                              -p/-H/-K it IS the credential (WinRM certificate
                              authentication); with them it is presented in the
                              TLS handshake alongside NTLM/Kerberos
  -k, --priv-key PATH         client private key (with -c)
      --proxy URL             reach the target through a SOCKS5 proxy, e.g.
                              socks5://127.0.0.1:1080 (or $WSMANCER_PROXY);
                              user:pass@ is accepted. The target's name is
                              resolved at the proxy, so an internal FQDN works.
                              Needed for a pivot: proxychains cannot wrap this
                              binary, it is static and never calls libc connect

TLS server verification (HTTPS verifies against the system roots by default):
      --ca-cert PATH          also trust this PEM CA when verifying the target
      --accept-fingerprint FP pin the target cert by SHA-256 (hex); safe for
                              self-signed certs whose hash you know in advance
      --insecure              skip verification entirely, encrypted but
                              MITM-vulnerable; last resort

Authentication:
  -u, --user USER             username (required unless using -K)
  -p, --password PASS         password (or $WSMANCER_PASSWORD; prompted for
                              if neither is given and stdin is a terminal)
  -H, --hash NTHASH           NT hash, pass-the-hash
  -K, --ccache PATH           Kerberos ticket: ccache or kirbi (auto-detected,
                              base64 kirbi accepted)
  -r, --realm DOMAIN          Kerberos realm / NTLM domain
      --spn PREFIX            SPN prefix for Kerberos (default HTTP)
      --skew SECONDS          add SECONDS to the Kerberos AP-REQ timestamp,
                              for targets whose clock is ahead

Execution and output:
  -x, --command CMD           run one command, print the result, exit;
                              -x - reads commands from stdin (one per line) and
                              runs them over one connection (batch mode)
  -o, --output text|json      output format (default text); json emits one
                              object per command with all PowerShell streams
      --chunk-size KB         bytes per round trip for upload/download
                              (default 192; raise for speed, lower if the
                              target rejects it with HTTP 413)
  -s, --scripts PATH          local directory of PowerShell scripts
  -e, --executables PATH      local directory of .NET executables; a bare name
                              passed to invoke-binary resolves here, and its
                              .exe files Tab-complete
  -Y, --history               keep command history on disk across sessions,
                              per target (default off: history is memory-only
                              because commands carry hashes and passwords).
                              Prefix a command with a space to keep that one
                              line out of the file. $WSMANCER_HISTORY_DIR
                              overrides ~/.wsmancer/history
      --history-tag NAME      name the history file (default: the target), so
                              several boxes can share one history or one box
                              can keep several
  -l, --log                   write a timestamped transcript to
                              ~/.wsmancer/logs/<host>/ ($WSMANCER_LOG_DIR)
  -n, --no-colors             disable colors
  -N, --no-rpath-completion   disable remote path completion

  -V, --version               print version
  -h, --help                  this message
`

func PrintUsage(w io.Writer) { fmt.Fprint(w, usage) }
