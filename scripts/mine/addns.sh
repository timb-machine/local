#!/bin/sh

DOMAINNAME="${1}"
DNSSERVER="${2}"

sites() {
	domainname="${1}"
	dnsserver="${2}"
	for businessunit in _sites
	do
		for defaultzone in Default-First-Site-Name
		do
			for serviceprotocol in _tcp _udp
			do
				for servicename in _gc _kerberos _ldap _kpasswd _autodiscover
				do
					printf "I: %s in " "${servicename}.${serviceprotocol}.${defaultzone}.${businessunit}.${domainname}"
					result="$(dig +short srv "${servicename}.${serviceprotocol}.${defaultzone}.${businessunit}.${domainname}" "@${dnsserver}")"
					if [ -z "${result}" ]
					then
						printf "UNKNOWN\n"
					else
						printf "%s\n" "${result}"
					fi
				done
			done
		done
	done
}

if [ -z "${DOMAINNAME}" ]
then
	printf "extracting DNS domain\n"
	DOMAINNAME="$(dig +short "@${DNSSERVER}" soa 255.in-addr.arpa | cut -f 1 -d " " | cut -f 2- -d ".")"
	printf "domain is: %s\n" "${DOMAINNAME}"
fi
for serviceprotocol in _tcp _udp
do
	for servicename in _gc _kerberos _ldap _kpasswd _autodiscover
	do
		printf "I: %s in " "${servicename}.${serviceprotocol}.${DOMAINNAME}"
		result="$(dig +short srv "${servicename}.${serviceprotocol}.${DOMAINNAME}" "@${DNSSERVER}")"
		if [ -z "${result}" ]
		then
			printf "UNKNOWN\n"
		else
			printf "%s\n" "${result}"
		fi
	done
done
sites "${DOMAINNAME}" "${DNSSERVER}"
for adzone in _msdcs
do
	for systemtype in dc domains gc pdc
	do
		sites "${systemtype}.${adzone}.${DOMAINNAME}" "${DNSSERVER}"
		for serviceprotocol in _tcp _udp
		do
			for servicename in _gc _kerberos _ldap _kpasswd _autodiscover
			do
				printf "I: %s in " "${servicename}.${serviceprotocol}.${systemtype}.${adzone}.${DOMAINNAME}"
				result="$(dig +short srv "${servicename}.${serviceprotocol}.${systemtype}.${adzone}.${DOMAINNAME}" "@${DNSSERVER}")"
				if [ -z "${result}" ]
				then
					printf "UNKNOWN\n"
				else
					printf "%s\n" "${result}"
				fi
			done
		done
	done
done
