#!/bin/sh

connect=${1:-127.0.0.1:1234}
openssl s_client -connect $connect \
	-CAfile ws1/ca-chain.cert.pem \
	-cert ws1/6d780e84-d6f3-4824-bcbe-c055ee602039.cert.pem \
	-key ws1/6d780e84-d6f3-4824-bcbe-c055ee602039.key.pem
