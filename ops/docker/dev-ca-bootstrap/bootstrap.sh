#!/bin/sh
# Dev CA + gateway server cert bootstrap (SEC-9: DEV ONLY, never production).
#
# Populates the named volume mounted at $CERT_DIR (default /certs):
#   dev-ca.crt   — issuing CA cert. Trust anchor for: nginx client verify
#                  (agent mTLS), agents verifying the gateway (SOC_CA_CERT_PATH).
#   dev-ca.key   — CA private key, used by dataplane-api to sign device CSRs
#                  (DP_CA_CERT/DP_CA_KEY). Owned by uid 10001 (soc runtime user).
#   gateway.crt  — gateway server cert for :8443, signed by the dev CA
#                  (SAN: gateway, localhost, 127.0.0.1).
#   gateway.key  — owned by uid 101 (nginx-unprivileged).
#
# Idempotent: exits 0 without touching anything if the CA already exists.
set -eu

CERT_DIR="${CERT_DIR:-/certs}"
CA_DAYS="${CA_DAYS:-730}"
GATEWAY_DAYS="${GATEWAY_DAYS:-398}"
DATAPLANE_UID="${DATAPLANE_UID:-10001}"   # keep in sync with ops/docker/python.Dockerfile
GATEWAY_UID="${GATEWAY_UID:-101}"         # nginx-unprivileged

if [ -f "$CERT_DIR/dev-ca.crt" ] && [ -f "$CERT_DIR/dev-ca.key" ] \
   && [ -f "$CERT_DIR/gateway.crt" ] && [ -f "$CERT_DIR/gateway.key" ]; then
    echo "dev-ca-bootstrap: CA and gateway cert already present in $CERT_DIR — nothing to do."
    exit 0
fi

echo "dev-ca-bootstrap: generating dev CA + gateway server cert in $CERT_DIR (DEV ONLY, SEC-9)"
umask 077
cd "$CERT_DIR"

# --- issuing CA (EC P-256, matches dataplane's expected key types) ----------
openssl ecparam -name prime256v1 -genkey -noout -out dev-ca.key
openssl req -x509 -new -key dev-ca.key -sha256 -days "$CA_DAYS" \
    -subj "/O=SOC POC/CN=SOC POC Dev Issuing CA" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -out dev-ca.crt

# --- gateway server cert (agents connect to https://gateway:8443) -----------
openssl ecparam -name prime256v1 -genkey -noout -out gateway.key
openssl req -new -key gateway.key -subj "/O=SOC POC/CN=gateway" -out gateway.csr

cat > gateway-ext.cnf <<'EOF'
subjectAltName = DNS:gateway, DNS:localhost, IP:127.0.0.1
extendedKeyUsage = serverAuth
keyUsage = critical, digitalSignature, keyAgreement
basicConstraints = CA:FALSE
EOF

openssl x509 -req -in gateway.csr -CA dev-ca.crt -CAkey dev-ca.key \
    -CAcreateserial -sha256 -days "$GATEWAY_DAYS" \
    -extfile gateway-ext.cnf -out gateway.crt
rm -f gateway.csr gateway-ext.cnf dev-ca.srl

# --- ownership/permissions (least privilege a shared volume allows) ---------
chmod 0644 dev-ca.crt gateway.crt
chmod 0600 dev-ca.key gateway.key
chown "$DATAPLANE_UID":"$DATAPLANE_UID" dev-ca.key
chown "$GATEWAY_UID":"$GATEWAY_UID" gateway.key

echo "dev-ca-bootstrap: done."
openssl x509 -in dev-ca.crt -noout -subject -enddate
openssl x509 -in gateway.crt -noout -subject -enddate
