#!/usr/bin/env bash
# Generate a local CA and a leaf certificate covering every lab origin.
#
# HTTPS matters here even though everything is on 127.0.0.1: a number of the
# primitives under test are gated on a secure context (Navigation API,
# SharedArrayBuffer, some COOP/COEP behaviour), and "https://victim.sop-lab.test"
# is a secure context while "http://victim.sop-lab.test" is not. Only
# http://localhost gets the secure-context exemption, and localhost cannot give
# us sibling subdomains for the document.domain probes.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/certs"
mkdir -p "$DIR"

if [ -f "$DIR/leaf.crt" ] && [ -f "$DIR/leaf.key" ] && [ -f "$DIR/ca.crt" ]; then
  echo "certs already present in $DIR (delete the directory to regenerate)"
  exit 0
fi

cat > "$DIR/leaf.cnf" <<'CNF'
[req]
distinguished_name = dn
req_extensions     = ext
prompt             = no
[dn]
CN = victim.sop-lab.test
[ext]
basicConstraints = CA:FALSE
keyUsage         = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName   = @san
[san]
DNS.1 = victim.sop-lab.test
DNS.2 = sub.victim.sop-lab.test
DNS.3 = attacker.sop-lab.test
DNS.4 = sop-lab.test
DNS.5 = documented.sop-lab.test
DNS.6 = localhost
IP.1  = 127.0.0.1
CNF

# Root CA
openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
  -subj "/CN=SOP Lab Local Root CA" \
  -keyout "$DIR/ca.key" -out "$DIR/ca.crt" 2>/dev/null

# Leaf CSR + signature, carrying the SAN list above.
openssl req -newkey rsa:2048 -nodes \
  -keyout "$DIR/leaf.key" -out "$DIR/leaf.csr" \
  -config "$DIR/leaf.cnf" 2>/dev/null

openssl x509 -req -in "$DIR/leaf.csr" \
  -CA "$DIR/ca.crt" -CAkey "$DIR/ca.key" -CAcreateserial \
  -days 3650 -extensions ext -extfile "$DIR/leaf.cnf" \
  -out "$DIR/leaf.crt" 2>/dev/null

rm -f "$DIR/leaf.csr"
chmod 600 "$DIR"/*.key

echo "generated CA + leaf in $DIR"
openssl x509 -in "$DIR/leaf.crt" -noout -ext subjectAltName
