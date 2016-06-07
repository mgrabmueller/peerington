#!/bin/sh

connect=${1:-127.0.0.1:1234}
openssl s_client -connect $connect \
	-CAfile ws1/ca-chain.cert.pem \
	-cert ws1/1e60b248-ff2e-4dc1-87d5-afe70107b112.cert.pem \
	-key ws1/1e60b248-ff2e-4dc1-87d5-afe70107b112.key.pem
