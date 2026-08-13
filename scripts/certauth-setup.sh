#!/usr/bin/env bash
# Configure (or tear down) a target for WinRM client-certificate authentication,
# and mint the client PKI that goes with it.
#
# Certificate auth is the one mode that cannot be tested against a stock box: the
# target has to be told, in advance, which certificate maps to which account. So
# the setup IS part of the test, and it lives here rather than in a README where
# it would rot.
#
# What it does to the target (all of it undone by --teardown):
#   * a self-signed server certificate + an HTTPS listener on 5986
#   * Service\Auth\Certificate = true
#   * imports the client CA into LocalMachine\Root
#   * maps <upn> issued by that CA to the account whose credentials are given
#   * opens 5986 inbound
#
# Locally it writes ca.crt/ca.key, client.crt/client.key (the good pair) and
# rogue.crt/rogue.key (a well-formed certificate from a CA the target does not
# trust, the negative control) into <outdir>, plus env.sh with the values the
# test harness needs.
#
# MAP_USER/MAP_UPN/MAP_PASS name the account the certificate maps to; there is
# no default, because a mapping is only meaningful against a real account on
# your own target.
#
#   MAP_USER='CORP\svc-account' MAP_UPN=svc-account@corp.local MAP_PASS=... \
#     scripts/certauth-setup.sh dc01.corp.local Administrator <nthash> /tmp/ca-lab
#   ... same, plus --teardown, to undo all of it
set -euo pipefail

HOST=${1:?usage: certauth-setup.sh <host> <admin-user> <nthash> <outdir> [--teardown]}
ADMIN=${2:?admin user}
HASH=${3:?admin NT hash}
OUT=${4:?output directory}
MODE=${5:-setup}

# The account the certificate maps to, and its password. It must be an account
# that may use WinRM; the mapping is checked against it at logon time.
MAP_USER=${MAP_USER:?set MAP_USER to the mapped account, e.g. CORP\\svc-account}
MAP_PASS=${MAP_PASS:?set MAP_PASS to the password of the mapped account}
MAP_UPN=${MAP_UPN:?set MAP_UPN to the UPN the certificate carries}

CD=$(cd "$(dirname "$0")/.." && pwd)
WSM="$CD/wsmancer"
admin() { timeout 180 "$WSM" -i "$HOST" -u "$ADMIN" -H "$HASH" -x "$1" 2>&1; }

if [[ "$MODE" == "--teardown" ]]; then
  echo "== tearing down $HOST =="
  admin '
    Get-ChildItem WSMan:\localhost\ClientCertificate | Remove-Item -Recurse -Force -EA SilentlyContinue
    Get-ChildItem WSMan:\localhost\Listener | ? { $_.Keys -contains "Transport=HTTPS" } |
      Remove-Item -Recurse -Force -EA SilentlyContinue
    Set-Item WSMan:\localhost\Service\Auth\Certificate $false -EA SilentlyContinue
    Get-ChildItem Cert:\LocalMachine\Root | ? { $_.Subject -eq "CN=wsmancer test CA" } | Remove-Item -Force
    Get-ChildItem Cert:\LocalMachine\My   | ? { $_.Subject -eq "CN='"$HOST"'" }             | Remove-Item -Force
    Remove-NetFirewallRule -DisplayName WinRM-HTTPS-5986 -EA SilentlyContinue
    Remove-Item C:\Windows\Temp\wsm-ca.crt -EA SilentlyContinue
    "torn down; cert auth now: " + (Get-Item WSMan:\localhost\Service\Auth\Certificate).Value
  ' | tail -2
  exit 0
fi

mkdir -p "$OUT"
cd "$OUT"

echo "== minting the client PKI in $OUT =="
cat > client.cnf <<'EOF'
[req]
distinguished_name = dn
prompt = no
[dn]
CN = winrm-client
[ext]
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
EOF
# The UPN goes in a SAN otherName, which is what Windows matches the mapping's
# -Subject against. A certificate without it authenticates as nobody.
printf 'subjectAltName = otherName:msUPN;UTF8:%s\n' "$MAP_UPN" >> client.cnf

mkcert() { # mkcert <ca-prefix> <leaf-prefix> <ca-cn>
  openssl req -x509 -newkey rsa:2048 -sha256 -days 30 -nodes -keyout "$1.key" -out "$1.crt" \
    -subj "/CN=$3" -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
  openssl req -new -newkey rsa:2048 -nodes -keyout "$2.key" -out "$2.csr" -config client.cnf 2>/dev/null
  openssl x509 -req -in "$2.csr" -CA "$1.crt" -CAkey "$1.key" -CAcreateserial -out "$2.crt" \
    -days 30 -sha256 -extfile client.cnf -extensions ext 2>/dev/null
}
mkcert ca    client "wsmancer test CA"
# The rogue pair is identical in every respect except its issuer, so a target
# that accepts it is not checking the chain at all.
mkcert rogue-ca rogue "wsmancer ROGUE CA"

echo "== configuring $HOST =="
FP=$(admin '
  $c = Get-ChildItem Cert:\LocalMachine\My | ? { $_.Subject -eq "CN='"$HOST"'" } | Select -First 1
  if (-not $c) { $c = New-SelfSignedCertificate -DnsName '"$HOST"' -CertStoreLocation Cert:\LocalMachine\My }
  # -Force does NOT replace an existing WSMan listener, it fails on it, so the
  # old one has to go first or a second run of this script dies here.
  Get-ChildItem WSMan:\localhost\Listener | ? { $_.Keys -contains "Transport=HTTPS" } |
    Remove-Item -Recurse -Force -EA SilentlyContinue
  New-Item -Path WSMan:\localhost\Listener -Transport HTTPS -Address * -CertificateThumbPrint $c.Thumbprint -Force | Out-Null
  Set-Item WSMan:\localhost\Service\Auth\Certificate $true
  New-NetFirewallRule -DisplayName WinRM-HTTPS-5986 -Direction Inbound -LocalPort 5986 -Protocol TCP -Action Allow -EA SilentlyContinue | Out-Null
  [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($c.RawData)).Replace("-","")
' | tail -1 | tr -d '\r')
echo "   server fingerprint: $FP"

CA_B64=$(base64 -w0 ca.crt)
THUMB=$(admin "
  [IO.File]::WriteAllBytes('C:\\Windows\\Temp\\wsm-ca.crt', [Convert]::FromBase64String('$CA_B64'))
  Get-ChildItem Cert:\\LocalMachine\\Root | ? { \$_.Subject -eq 'CN=wsmancer test CA' } | Remove-Item -Force
  (Import-Certificate -FilePath C:\\Windows\\Temp\\wsm-ca.crt -CertStoreLocation Cert:\\LocalMachine\\Root).Thumbprint
" | tail -1 | tr -d '\r')
echo "   client CA thumbprint: $THUMB"

admin "
  \$p = ConvertTo-SecureString '$MAP_PASS' -AsPlainText -Force
  \$cred = New-Object System.Management.Automation.PSCredential('$MAP_USER', \$p)
  Get-ChildItem WSMan:\\localhost\\ClientCertificate | Remove-Item -Recurse -Force -EA SilentlyContinue
  New-Item -Path WSMan:\\localhost\\ClientCertificate -Subject '$MAP_UPN' -URI * -Issuer '$THUMB' -Credential \$cred -Force | Out-Null
  'mapping: ' + (Get-ChildItem WSMan:\\localhost\\ClientCertificate).Keys
" | tail -1

cat > env.sh <<EOF
export CERTAUTH_HOST=$HOST
export CERTAUTH_FP=$FP
export CERTAUTH_ISSUER=$THUMB
export CERTAUTH_CERT=$OUT/client.crt
export CERTAUTH_KEY=$OUT/client.key
export CERTAUTH_ROGUE_CERT=$OUT/rogue.crt
export CERTAUTH_ROGUE_KEY=$OUT/rogue.key
export CERTAUTH_MAP_UPN=$MAP_UPN
EOF
echo "== done; source $OUT/env.sh =="
