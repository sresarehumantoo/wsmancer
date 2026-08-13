module github.com/sresarehumantoo/wsmancer

go 1.25.0

require (
	github.com/go-krb5/krb5 v0.0.0-20251226122733-d0288459fc25
	github.com/go-krb5/x v0.3.2
	github.com/reeflective/readline v1.3.0
	github.com/smnsjas/go-psrp v0.2.0
	github.com/smnsjas/go-psrpcore v0.0.0-20260211164949-dace42c5b6a8
	golang.org/x/crypto v0.48.0
	golang.org/x/net v0.50.0
	golang.org/x/sys v0.45.0
	golang.org/x/term v0.40.0
)

require (
	github.com/Azure/go-ntlmssp v0.1.0 // indirect
	github.com/Microsoft/go-winio v0.6.2 // indirect
	github.com/alexbrainman/sspi v0.0.0-20250919150558-7d374ff0d59e // indirect
	github.com/go-crypt/x v0.4.10 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/rivo/uniseg v0.4.7 // indirect
)

replace github.com/smnsjas/go-psrp => ./go-psrp-fork
