#!/bin/sh

ZONE="${1}"
VMNAME="${2}"
COMMANDSTRING="${3}"

while [ -z "${ipaddress}" ]
do
	macaddress="`virsh --connect "qemu:///system" domiflist "${VMNAME}" | grep "${ZONE}" | awk "{print $5}"`"
	ipaddress="`/usr/sbin/arp -an | grep "${macaddress}" | awk "{print $2}" | tr -d "()"`"
done
ssh -X "tmb@${ipaddress}" "${COMMANDSTRING}"
