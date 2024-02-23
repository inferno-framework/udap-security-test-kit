#!/usr/bin/env bash

echo "Now generating CA private key"
openssl genrsa -out InfernoCA.key 4096

echo "CA private key generated"

echo "Now generating self-signed CA cert"
openssl req -x509 -new -nodes -key InfernoCA.key -sha256 -days 3650 -subj "/C=US/ST=MA/L=Bedford/O=Inferno/CN=Inferno-UDAP-Root-CA/emailAddress=inferno@groups.mitre.org" -out InfernoCA.pem

echo "Self-signed CA cert generated"

echo "Now generating client private key"
openssl genrsa -out TestClientPrivateKey.key 2048

echo "Client private key generated"

echo "Now generating client's certificate signing request"
openssl req -new -key TestClientPrivateKey.key -subj "/C=US/ST=MA/L=Bedford/O=Inferno/CN=UDAP Example Test Client" -addext "subjectAltName=URI:https://inferno.com/udap_security/" -out TestClientCSR.csr
echo "Client's certificate signing request generated"

echo "Now generating client certificate using extension file & signing with CA"
openssl x509 -req -in TestClientCSR.csr -CA InfernoCA.pem -CAkey InfernoCA.key -CAcreateserial -out TestClient.pem -days 3650 -sha256 -extfile v3_ac.ext

echo "Client certificate generated and signed"

echo "Now creating a cert chain of client and CA certs"
# Validate the contents of the certificate
openssl x509 -in TestClient.pem -noout -text
echo "Cert chain generated"
echo "Script complete"