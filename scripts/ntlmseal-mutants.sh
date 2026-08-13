#!/usr/bin/env bash
#
# Differential for internal/auth/ntlmseal's unit tests: break the production
# code one way at a time and confirm the tests notice. Needs no target, this is
# the one harness in scripts/ that runs anywhere, including CI.
#
# It exists because the package's tests split into two kinds with very different
# power, and only a differential shows which is carrying which mutant:
#
#   message_test.go / httpseal_test.go  recompute expected values with the same
#       primitives the production code uses. They pin *layout*, offsets,
#       lengths, keystream alignment, and a self-consistent implementation of
#       the wrong algorithm sails straight through them.
#   vectors_test.go                     compares against MS-NLMP's published
#       values. Independent ground truth, and the only thing that catches a
#       mutant which stays self-consistent across both ends of the session.
#
# Five mutants below are caught ONLY by vectors_test.go: ntowfv2's upper-case,
# wrap signing the ciphertext, sealKey/signKey swapping direction, ntlmv2Temp
# dropping the trailing Z(4), and the LM response being zeroed only when a
# timestamp is present. Each is tagged [vectors-only] at its call below. If a
# future refactor deletes that file, this script says so immediately.
#
# That count is load-bearing and has been wrong twice, so it is measured, not
# copied forward: move vectors_test.go aside and re-run, and exactly those five
# go MISSED. Re-measure whenever a mutant or a test moves.
#
#   2026-07-31  five (the comment said three at the time, having missed the two
#               most recently added).
#   2026-08-02  re-measured, still those same five: baseline 20/20 caught,
#               vectors aside 15 caught / 5 MISSED. What was stale was not the
#               count but the section divider below, which grouped six mutants
#               as vectors-only; hence the per-mutant tags now.
#
# Usage: scripts/ntlmseal-mutants.sh [name-substring]
#
# Exit status is 0 only if every mutant was CAUGHT. A mutant that fails to
# compile (INVALID) or whose patch no longer matches the source (SKIP) proves
# nothing and is treated as failure, that is the trap this harness hit itself:
# renaming rand.Read to randRead silently turned one patch into a no-op, and an
# earlier version of this script reported the result as a genuine MISSED.
set -u

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
SRC="$ROOT/internal/auth/ntlmseal/ntlmseal.go"
FILTER="${1:-}"

BAK=$(mktemp); cp "$SRC" "$BAK"
trap 'cp "$BAK" "$SRC"; rm -f "$BAK"' EXIT

caught=0; failed=0

run_mutant() {
  local name="$1"; shift
  if [[ -n "$FILTER" && "$name" != *"$FILTER"* ]]; then return; fi
  cp "$BAK" "$SRC"
  perl -0pi -e "$1" "$SRC"

  # A patch that no longer matches leaves the good build in place; reporting
  # that as a pass would be a lie about coverage.
  if cmp -s "$BAK" "$SRC"; then
    printf 'SKIP    %s\n        patch no longer matches the source, fix the pattern\n' "$name"
    failed=$((failed + 1)); return
  fi

  local out
  out=$(cd "$ROOT" && go test ./internal/auth/ntlmseal/ 2>&1)

  # A mutant that does not compile re-tests nothing.
  if grep -qE "build failed|syntax error|undefined:|cannot use|declared and not used" <<<"$out"; then
    printf 'INVALID %s\n        mutant did not compile, differential proves nothing\n' "$name"
    failed=$((failed + 1)); return
  fi

  if grep -q "^ok" <<<"$out"; then
    printf 'MISSED  %s\n        tests PASS against the broken build\n' "$name"
    failed=$((failed + 1)); return
  fi

  local which
  which=$(grep -oE -- '--- FAIL: [^ ]+' <<<"$out" | sed 's/--- FAIL: //' | head -3 | tr '\n' ' ')
  printf 'CAUGHT  %-52s <- %s\n' "$name" "$which"
  caught=$((caught + 1))
}

# --- layout and framing: caught by message_test.go / httpseal_test.go --------
run_mutant "type3 header length off by 8" \
  's/const headerLen = 88/const headerLen = 80/'
run_mutant "wrapHTTP declares the sealed length" \
  's/Length=%d\\r\\n", len\(plain\)/Length=%d\\r\\n", len(plain)+16/'
run_mutant "timestamp walks past MsvAvEOL" \
  's/if id == 0 \{ \/\/ MsvAvEOL\n\t\t\tbreak\n\t\t\}//'
run_mutant "unwrap stops consuming the checksum keystream" \
  's/\tgot := make\(\[\]byte, 8\)\n\tk\.serverSeal\.XORKeyStream\(got, sig\[4:12\]\)/\tgot := make([]byte, 8)\n\tcopy(got, sig[4:12])/'
run_mutant "unwrap accepts any signature" \
  's/if !hmac\.Equal\(got, mac\.Sum\(nil\)\[:8\]\)/if false \&\& !hmac.Equal(got, mac.Sum(nil)[:8])/'
run_mutant "unwrap ignores the sequence number" \
  's/\tif declared := binary\.LittleEndian\.Uint32\(sig\[12:16\]\); declared != k\.serverSeq \{\n\t\treturn nil, fmt\.Errorf\("%w: got %d, expected %d", errOutOfSequence, declared, k\.serverSeq\)\n\t\}\n//'
# The transport half of the same check. unwrap can return the right error and
# still be ignored: before this, an out-of-sequence message fell into sealed()'s
# "not really ours" branch, so the caller got raw ciphertext on a still-open
# connection. Found live, not by the unit tests, hence this mutant.
run_mutant "out-of-sequence downgraded to a parse failure" \
  's/return errors\.Is\(err, errBadSignature\) \|\| errors\.Is\(err, errOutOfSequence\)/return errors.Is(err, errBadSignature)/'
run_mutant "unwrap verifies the ciphertext instead of the plaintext" \
  's/\tmac\.Write\(seq\)\n\tmac\.Write\(plain\)\n\n\t\/\/ Constant-time/\tmac.Write(seq)\n\tmac.Write(sealed)\n\n\t\/\/ Constant-time/'
run_mutant "parseType2 drops the target-info bounds check" \
  's/if tiLen > 0 && int\(tiOff\)\+int\(tiLen\) <= len\(b\)/if tiLen > 0 \&\& int(tiOff) <= len(b)/'
run_mutant "type3 reuses a fixed client challenge" \
  's/clientChallenge := make\(\[\]byte, 8\)\n\tif _, err = rand\.Read\(clientChallenge\); err != nil \{\n\t\treturn nil, nil, err\n\t\}/clientChallenge := make([]byte, 8)/'
run_mutant "type3 drops the server target info from temp" \
  's/ntlmv2Temp\(timestamp\(ch\.targetInfo\), clientChallenge, ch\.targetInfo\)/ntlmv2Temp(timestamp(ch.targetInfo), clientChallenge, nil)/'
run_mutant "type1 stops negotiating key exchange" \
  's/negAlwaysSign \| negExtendedSec \| negVersion \| neg128 \| negKeyExch \| neg56/negAlwaysSign | negExtendedSec | negVersion | neg128 | neg56/'
run_mutant "MIC is computed over the wrong messages" \
  's/micMac\.Write\(t1\)/micMac.Write(t2)/'
# Models the conditional LmChallengeResponse the spec's own ComputeResponse
# implements: zeroed only when the challenge carries an MsvAvTimestamp.
# [vectors-only]
run_mutant "LM response is only zeroed when a timestamp is present" \
  's/\tlmResponse := make\(\[\]byte, 24\)\n/\tlmResponse := make([]byte, 24)\n\tif !bytes.Contains(ch.targetInfo, []byte{7, 0, 8, 0}) {\n\t\tlmResponse[0] = 1\n\t}\n/'

# --- cryptographic correctness ----------------------------------------------
# The mutants only vectors_test.go catches are tagged [vectors-only] individually
# rather than grouped under this divider. They are NOT contiguous, one sits
# above it (the LM response) and two below it are caught without vectors, and a
# block comment claiming otherwise is exactly how this drifted: it spanned six
# mutants when the true set is five. Re-measure by moving vectors_test.go aside
# and re-running; the tags and the header list must both match the result.
run_mutant "ntlmv2Temp swaps the timestamp and client challenge" \
  's/\tb\.Write\(ts\)                             \/\/ 8-byte FILETIME\n\tb\.Write\(clientChallenge\)/\tb.Write(clientChallenge)\n\tb.Write(ts)/'
# [vectors-only]
run_mutant "ntlmv2Temp drops the trailing Z(4)" \
  's/\tb\.Write\(targetInfo\)\n\tb\.Write\(\[\]byte\{0, 0, 0, 0\}\)\n\treturn b\.Bytes\(\)/\tb.Write(targetInfo)\n\treturn b.Bytes()/'
# [vectors-only]
run_mutant "ntowfv2 stops upper-casing the username" \
  's/utf16le\(strings\.ToUpper\(user\) \+ domain\)/utf16le(user + domain)/'
run_mutant "wrap leaves the checksum unencrypted" \
  's/k\.clientSeal\.XORKeyStream\(enc, checksum\)/copy(enc, checksum)/'
# [vectors-only]
run_mutant "wrap signs the ciphertext instead of the plaintext" \
  's/mac\.Write\(seq\)\n\tmac\.Write\(plain\)/mac.Write(seq)\n\tmac.Write(sealed)/'
# [vectors-only]
run_mutant "sealKey and signKey swap direction" \
  's/return md5concat\(exported, "session key to "\+dir\+" sealing key magic constant\\x00"\)/return md5concat(exported, "session key to server-to-client sealing key magic constant\\x00")/'

cp "$BAK" "$SRC"
echo
if [[ $((caught + failed)) -eq 0 ]]; then
  # "0/0 caught" would otherwise exit 0 and read as a clean run.
  echo "no mutants ran${FILTER:+, nothing matched filter '$FILTER'}"
  exit 1
fi
if [[ $failed -eq 0 ]]; then
  echo "$caught/$caught mutants caught."
else
  echo "$caught caught, $failed NOT caught, the suite has a blind spot."
fi
(cd "$ROOT" && go test ./internal/auth/ntlmseal/ >/dev/null 2>&1) \
  || { echo "FATAL: restored tree does not pass, check $SRC"; exit 1; }
exit $((failed > 0))
