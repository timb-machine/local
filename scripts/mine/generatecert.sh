#!/bin/sh

DOMAINNAME="${1}"

openssl genrsa -out "/etc/ssl/private/${DOMAINNAME}.key" 4096
openssl req -sha256 -new -key "/etc/ssl/private/${DOMAINNAME}.key" -out "/etc/ssl/private/${DOMAINNAME}.csr"
cat "/etc/ssl/private/${DOMAINNAME}.csr"
