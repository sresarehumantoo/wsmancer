// sealcheck drives the ntlmseal/krbseal sealing providers directly against a
// WinRM box, one auth mode per invocation, and prints "[+] pipeline done" on
// success. It is the driver scripts/verify-matrix.sh runs to prove the
// auth+sealing matrix live; it is not part of the shipped tool, but CI keeps it
// building because the matrix depends on it. Its flags map onto the providers'
// Config fields so a single mode can be exercised in isolation.
//
//	go run . -server 10.10.10.5 -user Administrator -pass 'Passw0rd!' -script 'whoami'
package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/sresarehumantoo/go-psrp/client"

	"github.com/sresarehumantoo/wsmancer/internal/auth/krbseal"
	"github.com/sresarehumantoo/wsmancer/internal/auth/ntlmseal"
)

func main() {
	server := flag.String("server", "", "WinRM host (IP or FQDN)")
	user := flag.String("user", "", "username")
	domain := flag.String("domain", "", "NTLM domain (e.g. corp.local)")
	pass := flag.String("pass", "", "password (or PSRP_PASSWORD env)")
	hash := flag.String("hash", "", "NT hash for pass-the-hash (LM:NT or bare NT)")
	seal := flag.Bool("seal", false, "use custom NTLM provider with message sealing + PtH")
	krb := flag.Bool("krb", false, "use go-psrp native Kerberos (ccache)")
	useKrbSeal := flag.Bool("krbseal", false, "use custom Kerberos provider with message sealing")
	spn := flag.String("spn", "", "service principal (e.g. HTTP/dc01.corp.local)")
	skew := flag.Int("skew", 0, "seconds to add to AP-REQ time (DC clock ahead)")
	noseal := flag.Bool("noseal", false, "with -krbseal: send plaintext (auth-only test)")
	ccache := flag.String("ccache", "", "path to Kerberos ccache (or KRB5CCNAME)")
	realm := flag.String("realm", "", "Kerberos realm (e.g. CORP.LOCAL)")
	krb5conf := flag.String("krb5conf", "", "path to krb5.conf")
	script := flag.String("script", "whoami; $PSVersionTable.PSVersion", "PS to run")
	tls := flag.Bool("tls", false, "use HTTPS/5986")
	flag.Parse()

	if *pass == "" {
		*pass = os.Getenv("PSRP_PASSWORD")
	}
	if *server == "" || *user == "" {
		fmt.Fprintln(os.Stderr, "need -server and -user")
		os.Exit(2)
	}

	cfg := client.DefaultConfig()
	cfg.Username = *user
	cfg.Domain = *domain
	cfg.Password = *pass
	cfg.AuthType = client.AuthNTLM // direct NTLM, the pentest path
	cfg.UseTLS = *tls
	cfg.InsecureSkipVerify = true
	cfg.Timeout = 120 * time.Second

	mode := "stock go-ntlmssp (no sealing)"
	if *useKrbSeal {
		prov, err := krbseal.New(krbseal.Config{
			TicketPath:         *ccache,
			Krb5ConfPath:       *krb5conf,
			SPN:                *spn,
			SkewSeconds:        *skew,
			InsecureSkipVerify: true,
			SealEnabled:        !*noseal,
		})
		if err != nil {
			die("krbseal.New", err)
		}
		cfg.CustomAuthenticator = prov
		mode = fmt.Sprintf("custom Kerberos + sealing (seal=%v)", !*noseal)
	} else if *krb {
		cfg.AuthType = client.AuthKerberos
		cfg.CCachePath = *ccache
		cfg.Realm = *realm
		cfg.Krb5ConfPath = *krb5conf
		mode = "go-psrp native Kerberos (ccache)"
	} else if *seal || *hash != "" {
		nt, err := parseNTHash(*hash)
		if err != nil {
			die("parse hash", err)
		}
		prov, err := ntlmseal.New(ntlmseal.Config{
			User:               *user,
			Domain:             *domain,
			Password:           *pass,
			NTHash:             nt,
			InsecureSkipVerify: true,
		})
		if err != nil {
			die("ntlmseal.New", err)
		}
		cfg.CustomAuthenticator = prov
		if nt != nil {
			mode = "custom NTLM: pass-the-hash + sealing"
		} else {
			mode = "custom NTLM: password + sealing"
		}
	}
	fmt.Printf("[*] auth mode: %s\n", mode)

	psrp, err := client.New(*server, cfg)
	if err != nil {
		die("client.New", err)
	}
	if os.Getenv("SPIKE_DEBUG") != "" {
		psrp.SetSlogLogger(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()

	fmt.Printf("[*] connecting to %s (NTLM as %s)...\n", psrp.Endpoint(), *user)
	if err := psrp.Connect(ctx); err != nil {
		die("Connect", err)
	}
	defer psrp.Close(ctx)
	fmt.Println("[+] runspace pool open")

	res, err := psrp.Execute(ctx, *script)
	if err != nil {
		die("Execute", err)
	}
	fmt.Printf("[+] pipeline done, %d output object(s):\n", len(res.Output))
	for _, o := range res.Output {
		fmt.Printf("    %v\n", o)
	}
}

func die(where string, err error) {
	fmt.Fprintf(os.Stderr, "[!] %s: %v\n", where, err)
	os.Exit(1)
}

// parseNTHash accepts "" (none), a bare 32-hex NT hash, or "LM:NT".
func parseNTHash(s string) ([]byte, error) {
	if s == "" {
		return nil, nil
	}
	if i := strings.LastIndex(s, ":"); i >= 0 {
		s = s[i+1:] // take NT half of aad3b...:NT
	}
	b, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, err
	}
	if len(b) != 16 {
		return nil, fmt.Errorf("NT hash must be 16 bytes (32 hex), got %d", len(b))
	}
	return b, nil
}
