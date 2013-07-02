#!/bin/sh

DOMAIN="$1"
DNSSERVER="$2"

if [ -z "$DOMAIN" ]
then
	printf "extracting DNS domain\n"
	DOMAIN="`dig +short "@$DNSSERVER" soa 255.in-addr.arpa | awk '{print $1}' | cut -f 2- -d"."`"
	printf "domain is: $DOMAIN\n"
fi

sites() {
	domain="$1"
	dnsserver="$2"
	for i in _sites
	do
		for j in Default-First-Site-Name
		do
			for k in _tcp _udp
			do
				for l in _gc _kerberos _ldap _kpasswd
				do
					printf "$l.$k.$j.$i.$domain in "
					result="`dig +short srv "$l.$k.$j.$i.$DOMAIN" "@$dnsserver"`"
						if [ -z "$result" ]
					then
						printf "UNKNOWN\n"
					else
						printf "$result\n"
					fi
				done
			done
		done
	done
}
for x in _tcp _udp
do
	for y in _gc _kerberos _ldap _kpasswd
	do
		printf "$y.$x.$DOMAIN in "
		result="`dig +short srv "$y.$x.$DOMAIN" "@$DNSSERVER"`"
		if [ -z "$result" ]
		then
			printf "UNKNOWN\n"
		else
			printf "$result\n"
		fi
	done
done
sites "$DOMAIN" "$DNSSERVER"
for x in _msdcs
do
	for y in dc domains gc pdc
	do
		sites "$y.$x.$DOMAIN" "$DNSSERVER"
		for z in _tcp _udp
		do
			for a in _gc _kerberos _ldap _kpasswd
			do
				printf "$a.$z.$y.$x.$DOMAIN in "
				result="`dig +short srv "$a.$z.$y.$x.$DOMAIN" "@$DNSSERVER"`"
				if [ -z "$result" ]
				then
					printf "UNKNOWN\n"
				else
					printf "$result\n"
				fi
			done
		done
	done
done
