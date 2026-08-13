#!/usr/bin/env bash
# Mint the two service tickets the Kerberos rows of verify-matrix.sh need:
#   lab/<user>@HTTP_<target>@<REALM>.ccache -> RC4 (etype 23) session key, legacy
#   lab/admincc                             -> AES256 (etype 18), the modern path
#
# Everything it writes goes to lab/, which is gitignored -- it is your own
# machine's engagement state and is not part of this repo.
#
# Getting an AES session key out of a DC is the fiddly part. impacket's getST
# downgrades and hands back RC4 no matter what enctypes you ask for, so the AES
# ticket comes from MIT `kvno` with an AES-only krb5.conf, reusing the impacket
# AES TGT (no keytab needed).
#
# faketime is used throughout because a lab DC's clock often runs minutes ahead
# and these are libc-based Python/MIT tools (it would NOT work on the Go binary).
#
# Target, realm and accounts all come from the environment -- nothing here is
# pinned to the box this was developed against:
#
#   KRBUSER=corp.local/svc-account KRBPASS='...' \
#   NT=<admin nt hash> AES=<admin aes256 key> TARGET=dc01.corp.local \
#     ./scripts/get-tickets.sh 10.10.10.5
set -euo pipefail

DCIP=${1:?usage: get-tickets.sh <dc-ip>}
CD=$(cd "$(dirname "$0")/.." && pwd)
# Tickets and the measured skew are engagement artifacts, not source: they live
# in lab/, which is gitignored whole and is not part of this repo.
LAB="$CD/lab"
mkdir -p "$LAB"
cd "$LAB"

# Privileged keys, from: secretsdump.py -just-dc-user Administrator -hashes :$NT
# Supplied by the caller: credentials do not belong in a tracked file, even a
# lab's. Same for KRBUSER/KRBPASS below, which mint the unprivileged TGT.
NT=${NT:?set NT to the admin account RC4/NT hash}
AES=${AES:?set AES to the admin account aes256 key}
KRBUSER=${KRBUSER:?set KRBUSER to the user whose TGT to mint, e.g. corp.local/svc-account}
KRBPASS=${KRBPASS:?set KRBPASS to the password for KRBUSER}
KRBREALM=${KRBUSER%%/*}          # corp.local/svc-account -> corp.local
TARGET=${TARGET:?set TARGET to the SPN host the service tickets are minted for}
# The account the AES ticket is minted for; needs the aes256 key above.
ADMINUSER=${ADMINUSER:-$KRBREALM/Administrator}

DCTIME=$(nmap -Pn -sT -p445 --script smb2-time "$DCIP" 2>/dev/null | awk -F'date: ' '/  date:/{print $2}')
SKEW=$(( $(date -u -d "$DCTIME" +%s) - $(date -u +%s) ))
echo "$SKEW" > "$LAB/skew.txt"
echo "== skew=${SKEW}s (also written to lab/skew.txt for -skew) =="

# Both krb5 configs are rendered per run, into lab/. The realm belongs to
# whoever is testing and MIT wants an address for the KDC rather than a name --
# and a lab box's address changes every spawn. Rendering keeps the tracked
# templates realm-neutral and stops a run from leaving the tree dirty.
render_krb5() {
  sed -e "s/@REALM@/${KRBREALM^^}/g" -e "s/@realm@/${KRBREALM,,}/g" \
      -e "s/@KDC@/$2/g" "$CD/scripts/$1.tmpl" > "$LAB/$1"
}
render_krb5 krb5.conf "$DCIP"
render_krb5 krb5-aes.conf "$DCIP"
export KRB5_CONFIG=$LAB/krb5.conf
FT=(faketime "+${SKEW} seconds")

KRBSHORT=${KRBUSER##*/}          # corp.local/svc-account -> svc-account
RC4CC="$KRBSHORT@HTTP_$TARGET@${KRBREALM^^}.ccache"

echo "-- RC4 path: $KRBSHORT TGT -> ST (impacket, yields etype 23) --"
rm -f "$KRBSHORT.ccache" "$RC4CC"
"${FT[@]}" getTGT.py "$KRBUSER:$KRBPASS" -dc-ip "$DCIP" >/dev/null
KRB5CCNAME=$LAB/$KRBSHORT.ccache "${FT[@]}" \
  getST.py -k -no-pass -spn "HTTP/$TARGET" "$KRBUSER" -dc-ip "$DCIP" >/dev/null

ADMINSHORT=${ADMINUSER##*/}
echo "-- AES path: $ADMINSHORT AES TGT, then MIT kvno to force an AES ST --"
rm -f "$ADMINSHORT.ccache" admincc
"${FT[@]}" getTGT.py "$ADMINUSER" -aesKey "$AES" -dc-ip "$DCIP" >/dev/null
cp "$ADMINSHORT.ccache" admincc
KRB5CCNAME=$LAB/admincc KRB5_CONFIG=$LAB/krb5-aes.conf "${FT[@]}" kvno "HTTP/$TARGET"

echo "-- resulting session-key enctypes --"
RC4CC="$RC4CC" python3 - <<'EOF'
import os
from impacket.krb5.ccache import CCache
names = {23: 'rc4-hmac', 18: 'aes256', 17: 'aes128'}
for f in (os.environ['RC4CC'], 'admincc'):
    for cr in CCache.loadFile(f).credentials:
        spn = cr['server'].prettyPrint().decode()
        kt = cr['key']['keytype']
        print(f"  {f:52s} {spn:34s} etype={kt} ({names.get(kt, '?')})")
EOF

echo
echo "== tickets in $LAB =="
echo "   MXCCACHE=$LAB/$RC4CC"
echo "   MXCCACHE_AES=$LAB/admincc"
