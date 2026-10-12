#!/usr/bin/env bash
# Generate a lab-only CA and a broker certificate. Output: broker/certs/ (git-ignored).
# The server cert covers localhost, 127.0.0.1 and "mosquitto" (the Docker service name).
set -euo pipefail
OUT="${1:-$(cd "$(dirname "$0")" && pwd)/certs}"
mkdir -p "$OUT"
cd "$OUT"

if [ -f ca.crt ] && [ -f server.crt ]; then
  echo "certs already exist in $OUT (delete them to regenerate)"
  exit 0
fi

openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout ca.key -out ca.crt -subj "/CN=IoTGuard Lab CA" 2>/dev/null

openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr \
  -subj "/CN=mosquitto" 2>/dev/null

cat > server.ext <<EOF
subjectAltName = DNS:localhost, DNS:mosquitto, IP:127.0.0.1
extendedKeyUsage = serverAuth
EOF

openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt -days 365 -extfile server.ext 2>/dev/null

rm -f server.csr server.ext ca.srl
chmod 600 ca.key server.key
chmod 644 server.key  # the broker (may run as user "mosquitto") must read it; lab only
echo "wrote CA + server cert to $OUT"
