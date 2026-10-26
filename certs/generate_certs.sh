#!/bin/bash

set -e

# ======================================================
# SecureProxy Certificate Generator
# ======================================================

CERT_DIR=$(pwd)

CA_DIR="$CERT_DIR/ca"
SERVER_DIR="$CERT_DIR/server"
CLIENT_DIR="$CERT_DIR/clients/tenantA"

echo "======================================"
echo " SecureProxy Certificate Generator"
echo "======================================"
cleanup() {

    echo "[0/4] Cleaning old certificates..."

    rm -f "$CA_DIR"/*.crt
    rm -f "$CA_DIR"/*.key
    rm -f "$CA_DIR"/*.srl

    rm -f "$SERVER_DIR"/*.crt
    rm -f "$SERVER_DIR"/*.csr
    rm -f "$SERVER_DIR"/*.key

    rm -f "$CLIENT_DIR"/*.crt
    rm -f "$CLIENT_DIR"/*.csr
    rm -f "$CLIENT_DIR"/*.key
}
generate_ca() {

    echo "[1/4] Generating Root CA..."

    openssl genrsa -out "$CA_DIR/ca.key" 4096

    openssl req \
        -x509 \
        -new \
        -nodes \
        -key "$CA_DIR/ca.key" \
        -sha256 \
        -days 3650 \
        -out "$CA_DIR/ca.crt" \
        -subj "/C=IN/ST=West Bengal/L=Kharagpur/O=IIT Kharagpur/OU=CSE/CN=SecureProxy Root CA"
}

generate_server() {

    echo "[2/4] Generating Server Certificate..."

    openssl genrsa \
        -out "$SERVER_DIR/server.key" \
        4096

    openssl req \
        -new \
        -key "$SERVER_DIR/server.key" \
        -out "$SERVER_DIR/server.csr" \
        -config "$SERVER_DIR/server.cnf"

    openssl x509 \
        -req \
        -in "$SERVER_DIR/server.csr" \
        -CA "$CA_DIR/ca.crt" \
        -CAkey "$CA_DIR/ca.key" \
        -CAcreateserial \
        -out "$SERVER_DIR/server.crt" \
        -days 365 \
        -sha256 \
        -extensions v3_req \
        -extfile "$SERVER_DIR/server.cnf"
}

generate_client() {

    echo "[3/4] Generating Client Certificate..."

    openssl genrsa \
        -out "$CLIENT_DIR/client.key" \
        4096

    openssl req \
        -new \
        -key "$CLIENT_DIR/client.key" \
        -out "$CLIENT_DIR/client.csr" \
        -config "$CLIENT_DIR/client.cnf"

    openssl x509 \
        -req \
        -in "$CLIENT_DIR/client.csr" \
        -CA "$CA_DIR/ca.crt" \
        -CAkey "$CA_DIR/ca.key" \
        -CAserial "$CA_DIR/ca.srl" \
        -out "$CLIENT_DIR/client.crt" \
        -days 365 \
        -sha256 \
        -extensions v3_req \
        -extfile "$CLIENT_DIR/client.cnf"
}

verify_certificates() {

    echo "[4/4] Verifying Certificates..."

    openssl verify -CAfile "$CA_DIR/ca.crt" "$SERVER_DIR/server.crt"
    openssl verify -CAfile "$CA_DIR/ca.crt" "$CLIENT_DIR/client.crt"

    echo
    echo "========== Server Certificate =========="
    openssl x509 -in "$SERVER_DIR/server.crt" -noout -subject -issuer

    echo
    echo "========== Client Certificate =========="
    openssl x509 -in "$CLIENT_DIR/client.crt" -noout -subject -issuer

    echo
    echo "All certificates verified successfully."
}

main() {

    cleanup
    generate_ca
    generate_server
    generate_client
    verify_certificates

    echo
    echo "Certificate generation completed."
}

main
