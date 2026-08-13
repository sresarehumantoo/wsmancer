#!/usr/bin/env bash
# Live verification matrix for the auth+sealing layer, against a stock WinRM
# target (AllowUnencrypted=false, HTTP/5985).
#
# Runs two CONTROLS first, without them a "pass" is meaningless, because a box
# with AllowUnencrypted=true accepts unsealed traffic and every test trivially
# succeeds.
#
# Prereqs: ./wsmancer-sealcheck built, and for the Kerberos rows a ccache holding an ST
# for $SPN. scripts/get-tickets.sh mints both and prints the MXCCACHE* values
# below; it also renders the krb5.conf this reads.
#
# Everything box-specific comes from the environment, never from this file,
# accounts and credentials because they must not be committed, the rest so the
# matrix runs against any target and not just the one it was written for:
#   MXUSER=svc-account MXDOMAIN=corp.local MXPASS=... MXHASH=<nthash> \
#   MXADMIN=Administrator \
#     ./scripts/verify-matrix.sh dc01.corp.local 10.10.10.5
set -u

MXUSER=${MXUSER:?set MXUSER to the account to authenticate as}
MXDOMAIN=${MXDOMAIN:?set MXDOMAIN to its domain}
MXPASS=${MXPASS:?set MXPASS to its password}
# The pass-the-hash row deliberately runs as the privileged account (MXADMIN
# below), so this is that account's hash, not MXUSER's.
MXHASH=${MXHASH:?set MXHASH to the NT hash of the pass-the-hash account}

HOST=${1:?usage: verify-matrix.sh <winrm-host> <dc-ip>}
DCIP=${2:?usage: verify-matrix.sh <winrm-host> <dc-ip>}
CD=$(cd "$(dirname "$0")/.." && pwd)
BIN=$CD/wsmancer-sealcheck
SPN=HTTP/$HOST

# The privileged account the AES rows run as, and the two ccaches + krb5.conf
# get-tickets.sh leaves in lab/. Defaults match its output, so a normal run
# needs none of these set.
MXADMIN=${MXADMIN:-Administrator}
MXCCACHE=${MXCCACHE:-$CD/lab/$MXUSER@HTTP_$HOST@${MXDOMAIN^^}.ccache}
MXCCACHE_AES=${MXCCACHE_AES:-$CD/lab/admincc}
MXKRB5CONF=${MXKRB5CONF:-$CD/lab/krb5.conf}

# The DC clock is often minutes ahead; the AP-REQ authenticator is stamped
# now+skew to compensate. faketime cannot fix this for a Go binary (Go issues
# clock_gettime directly, bypassing libc), hence the explicit -skew flag.
DCTIME=$(nmap -Pn -sT -p445 --script smb2-time "$DCIP" 2>/dev/null | awk -F'date: ' '/  date:/{print $2}')
SKEW=$(( $(date -u -d "$DCTIME" +%s) - $(date -u +%s) ))
echo "== target=$HOST dc=$DCIP skew=${SKEW}s =="

pass=0; fail=0
# expect=ok   -> the command must succeed
# expect=deny -> the command must be REJECTED (that is the point of a control)
run() {
  local name=$1 expect=$2; shift 2
  local out; out=$(timeout 120 "$@" 2>&1)
  local got=deny
  grep -q '^\[+\] pipeline done' <<<"$out" && got=ok
  if [[ $got == "$expect" ]]; then
    printf '  PASS  %-46s (%s)\n' "$name" "$got"; pass=$((pass+1))
  else
    printf '  FAIL  %-46s expected=%s got=%s\n' "$name" "$expect" "$got"; fail=$((fail+1))
    sed 's/^/          | /' <<<"$(tail -3 <<<"$out")"
  fi
}

echo "-- controls: prove the target actually enforces encryption --"
# If either of these passes, the target is NOT stock and the rows below prove nothing.
run "control: unsealed NTLM must be refused" deny \
  "$BIN" -server "$HOST" -user "$MXUSER" -domain "$MXDOMAIN" -pass "$MXPASS" -script whoami
run "control: Kerberos auth + plaintext body refused" deny \
  "$BIN" -server "$HOST" -user "$MXUSER" -krbseal -noseal \
  -ccache "$MXCCACHE" -krb5conf "$MXKRB5CONF" -spn "$SPN" -skew "$SKEW" -script whoami

echo "-- NTLM --"
run "NTLM password + seal" ok \
  "$BIN" -server "$HOST" -user "$MXUSER" -domain "$MXDOMAIN" -pass "$MXPASS" -seal -script whoami
run "NTLM pass-the-hash + seal" ok \
  "$BIN" -server "$HOST" -user "$MXADMIN" -domain "$MXDOMAIN" \
  -hash "$MXHASH" -script whoami

echo "-- Kerberos --"
run "Kerberos RC4 (etype 23) auth + seal" ok \
  "$BIN" -server "$HOST" -user "$MXUSER" -krbseal \
  -ccache "$MXCCACHE" -krb5conf "$MXKRB5CONF" -spn "$SPN" -skew "$SKEW" -script whoami
run "Kerberos AES256 (etype 18) auth + seal" ok \
  "$BIN" -server "$HOST" -user "$MXADMIN" -krbseal \
  -ccache "$MXCCACHE_AES" -krb5conf "$MXKRB5CONF" -spn "$SPN" -skew "$SKEW" -script whoami

echo "== pass=$pass fail=$fail =="
[[ $fail -eq 0 ]]
