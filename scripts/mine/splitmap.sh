#!/bin/sh

IPADDRESS="${1}"

for portnumber in $(seq 0 1000 64000)
do
	nmap -oA "sS-${portnumber}-$(expr "${portnumber}" + 1000)-${IPADDRESS}" -p "${portnumber}-$(expr "${portnumber}" + 1000)" -Pn -vv --reason "${IPADDRESS}"
done
nmap -oA "sS-65000-65535-${IPADDRESS}" -p 65000-65535 -Pn -vv --reason "${IPADDRESS}"
