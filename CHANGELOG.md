# Changelog

All notable changes to wsmancer are documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [0.2.1] - 2026-11-23

### Fixed
- Surface clear HTTP status errors in sealed transports (#2)
- Re-record demo against winforge

## [0.2.0] - 2026-11-21

### Added
- `bypass-clm` command (patches `GetSystemLockdownPolicy` to force FullLanguage)
- ETW patching in `bypass-4msi` (disables .NET ETW events)
- ScriptBlock logging disable in `bypass-4msi`
- `-q/--quiet` flag to suppress `Info:` lines on stderr
- `-T/--timeout` flag and `WSMANCER_TIMEOUT` env var
- Environment variables section in `--help`
- golangci-lint in CI
- Table-driven tests for pure functions

### Changed
- `bypass-4msi` patch bytes obfuscated to evade Win11 25H2 Defender
- `bypass-4msi` obfuscation seeded from crypto/rand
- Extracted `parseNTHash` and `psQuote` to `internal/psutil`

### Fixed
- golangci-lint findings: ineffassign, errcheck, SA1019
- gofmt on three files missed by a worktree agent
- British spellings (colour, behavioural, greyed, defence, cancelled)

## [0.1.2] - 2026-10-24

### Changed
- Updated dependencies

## [0.1.1] - 2026-09-27

### Added
- GoReleaser: release binaries on tag push

### Changed
- Updated dependencies; raised Go floor to 1.26

## [0.1.0] - 2026-08-13

### Added
- PSRP-native WinRM shell with typed JSON output (`-o json`)
- NTLM and Kerberos authentication with WinRM message sealing
- Pass-the-hash (`-H`), Kerberos ticket (`-K`), client certificate (`-c/-k`) auth
- Interactive shell with line editing, inline autosuggestion, command history
- Tab completion for local/remote paths, cmdlet names, parameters and values
- File transfer (upload/download) with SHA-256 verification and wildcards
- One-shot mode (`-x`) and batch mode (`-x -`) with NDJSON output
- Session recovery across dropped connections
- Forgotten-shell detection with loud state-loss announcement
- PowerShell script loading (`-s` + `menu`), `services` recon
- In-memory .NET execution (`invoke-binary`), shellcode injection (`donut-loader`)
- `bypass-4msi` (AMSI patch with per-invocation obfuscation)
- TLS verification: system roots, `--ca-cert`, `--accept-fingerprint`, `--insecure`
- SOCKS5 pivoting (`--proxy`)
- Session logging (`-l/--log`)
- Ctrl-C pipeline termination on the target
- Cross-platform static binaries

[Unreleased]: https://github.com/sresarehumantoo/wsmancer/compare/v0.2.1...HEAD
[0.2.1]: https://github.com/sresarehumantoo/wsmancer/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/sresarehumantoo/wsmancer/compare/v0.1.2...v0.2.0
[0.1.2]: https://github.com/sresarehumantoo/wsmancer/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/sresarehumantoo/wsmancer/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/sresarehumantoo/wsmancer/releases/tag/v0.1.0
