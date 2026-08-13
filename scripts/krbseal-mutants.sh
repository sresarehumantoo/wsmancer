#!/usr/bin/env bash
#
# Differential for internal/auth/krbseal's unit tests: break the production code
# one way at a time and confirm the tests notice. Needs no target, the second
# such harness in scripts/, after ntlmseal-mutants.sh, and it runs in CI for the
# same reason.
#
# It exists because this package's tests split into two kinds with very
# different power, and only a differential shows which is carrying which mutant:
#
#   seal_test.go     builds its input with the production `wrap` and asserts
#       `unwrap` reads it back. Pins layout, slicing and the tamper checks, and
#       a self-consistent implementation of the wrong algorithm round-trips
#       against itself perfectly and sails through every one of them.
#   vectors_test.go  compares against wrap tokens produced by impacket, an
#       independent implementation of the same RFCs. That is the only thing
#       catching a mutant which stays self-consistent across both ends.
#
# The RC4 path is why this matters. There krbseal hand-rolls RFC 4757 §7.3's
# HMAC-MD5 chains rather than delegating to a cryptosystem, so a wrong Kseq,
# Kcrypt or SGN_CKSUM is invisible to anything that only talks to itself. On the
# AES path the payload crypto is go-krb5's and vector-tested upstream; what the
# vectors add there is the key usage, which is ours to choose.
#
# Mutants that touch a derivation appearing in BOTH wrapRC4 and unwrapRC4 are
# applied globally on purpose, that IS the self-consistent class. Mutating one
# side only would be caught by any round-trip and would prove nothing.
#
# The vectors-only mutants are tagged [vectors-only] individually. That count is
# load-bearing, so it is measured, not copied forward, move vectors_test.go
# aside, re-run, and exactly those go MISSED:
#
#   2026-08-10  first measurement, when the vectors landed: baseline 14/14
#               caught; vectors aside 4 caught / 10 MISSED. The ten are every
#               RC4 crypto mutant (nine) plus the AES key-usage swap. The four
#               that survive without vectors are the three tamper-check
#               controls and the AES rotation, which TestSealPlumbing catches
#               because it asserts the recovered length as well as the prefix.
#
# Usage: scripts/krbseal-mutants.sh [name-substring]
#
# Exit status is 0 only if every mutant was CAUGHT. A mutant that fails to
# compile (INVALID) or whose patch no longer matches the source (SKIP) proves
# nothing and is treated as failure. Both traps are live here: deleting a
# comparison outright orphans the values it read and stops the package
# compiling, which is why the controls below neuter the condition with
# `if false && ...` rather than removing it.
set -u

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
SRC="$ROOT/internal/auth/krbseal/krbseal.go"
FILTER="${1:-}"

BAK=$(mktemp); cp "$SRC" "$BAK"
trap 'cp "$BAK" "$SRC"; rm -f "$BAK"' EXIT

caught=0; failed=0

run_mutant() {
  local name="$1"; shift
  if [[ -n "$FILTER" && "$name" != *"$FILTER"* ]]; then return; fi
  cp "$BAK" "$SRC"
  for pat in "$@"; do perl -0pi -e "$pat" "$SRC"; done

  # A patch that no longer matches leaves the good build in place; reporting
  # that as a pass would be a lie about coverage.
  if cmp -s "$BAK" "$SRC"; then
    printf 'SKIP    %s\n        patch no longer matches the source, fix the pattern\n' "$name"
    failed=$((failed + 1)); return
  fi

  local out
  out=$(cd "$ROOT" && go test ./internal/auth/krbseal/ 2>&1)

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
  printf 'CAUGHT  %-50s <- %s\n' "$name" "$which"
  caught=$((caught + 1))
}

# --- RC4: the hand-rolled RFC 4757 §7.3 crypto ------------------------------
# Every one of these is [vectors-only]. That is not a coincidence: the whole
# derivation chain is shared between wrapRC4 and unwrapRC4, so breaking it
# breaks both ends identically and the round-trip still closes.

# [vectors-only] 15 is the MIC constant; 13 is Wrap's. Swapping them is the
# single most plausible real misreading of the RFC.
run_mutant "SGN_CKSUM uses the MIC constant 15" \
  's/m\.Write\(le32\(13\)\)/m.Write(le32(15))/g'
# [vectors-only]
run_mutant "signaturekey loses its trailing NUL" \
  's/signaturekey\\x00/signaturekey/g'
# [vectors-only]
run_mutant "Kcrypt drops the 0xF0 xor" \
  's/xorF0\(key\)/key/g'
# [vectors-only]
run_mutant "Kseq nests its HMACs the other way round" \
  's/hmacMD5\(hmacMD5\(key, le32\(0\)\), sgn\)/hmacMD5(hmacMD5(key, sgn), le32(0))/g'
# [vectors-only]
run_mutant "Kcrypt keys on the sequence little-endian" \
  's/be32\(seq\)/le32(seq)/g'
# [vectors-only]
run_mutant "Kcrypt inner HMAC keys on 1 not 0" \
  's/xorF0\(key\), le32\(0\)/xorF0(key), le32(1)/g'
# [vectors-only]
run_mutant "SGN_CKSUM takes the wrong 8 bytes" \
  's/hmacMD5\(ksign, m\.Sum\(nil\)\)\[:8\]/hmacMD5(ksign, m.Sum(nil))[8:16]/g'
# [vectors-only] Only wrapRC4 writes first8; unwrapRC4 reads it back off the
# wire. So this one is invisible even to the vectors' own checksum
# recomputation, which uses the received copy, it is caught solely by
# TestRC4WrapAgainstDerivedKeyVectors asserting the header explicitly.
run_mutant "SEAL_ALG advertised as 0x11" \
  's/0x02, 0x01, 0x11, 0x00, 0x10, 0x00/0x02, 0x01, 0x11, 0x00, 0x11, 0x00/'
# [vectors-only]
run_mutant "checksum covers the payload before the confounder" \
  's/\tm\.Write\(conf\)\n\tm\.Write\(d\)/\tm.Write(d)\n\tm.Write(conf)/' \
  's/\tm\.Write\(conf\)\n\tm\.Write\(plain\)/\tm.Write(plain)\n\tm.Write(conf)/'

# --- AES: the parts of that path that are ours to get wrong -----------------
# [vectors-only] RFC 4121 derives a separate key per direction, so using the
# initiator usage at both ends is self-consistent and only an outside token
# notices. This is the mutant that would silently break interop with Windows.
run_mutant "AES seals and opens with the initiator usage" \
  's/keyusage\.GSSAPI_ACCEPTOR_SEAL/keyusage.GSSAPI_INITIATOR_SEAL/g'
run_mutant "AES rotation runs the wrong way at both ends" \
  's/token := append\(hdr, rotateRight\(ed\.Cipher, int\(rrc\)\)\.\.\.\)/token := append(hdr, rotateLeft(ed.Cipher, int(rrc))...)/' \
  's/cipher := rotateLeft\(token\[16:\], rrc\)/cipher := rotateRight(token[16:], rrc)/'

# --- controls: caught WITHOUT the vectors -----------------------------------
# These keep the measurement above honest. If one of them ever goes MISSED with
# vectors_test.go aside, the differential has stopped isolating what it claims.
run_mutant "[control] direction tag check deleted" \
  's/if !hmac\.Equal\(sndSeq\[4:8\], \[\]byte\{0xff, 0xff, 0xff, 0xff\}\)/if false/'
run_mutant "[control] SGN_CKSUM comparison deleted" \
  's/if !hmac\.Equal\(sgn, hmacMD5\(ksign, m\.Sum\(nil\)\)\[:8\]\)/if false \&\& !hmac.Equal(sgn, hmacMD5(ksign, m.Sum(nil))[:8])/'
run_mutant "[control] AES echoed-header comparison deleted" \
  's/if !hmac\.Equal\(echoed\[:4\], hdr\[:4\]\) \|\| !hmac\.Equal\(echoed\[8:\], hdr\[8:\]\)/if false/'

echo
if [[ $failed -gt 0 ]]; then
  echo "krbseal mutants: $caught caught, $failed NOT caught, the tests have a hole"
  exit 1
fi
echo "krbseal mutants: $caught/$caught caught"
