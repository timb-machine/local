#!/bin/sh

naslpluginsdirectorypath=/opt/nessus/lib/nessus/plugins
nasldbfilename=/usr/local/scripts/mine/naslplugins.txt

if [ "${1}" = "update" -o ! -f "${nasldbfilename}" ]
then
	find "${naslpluginsdirectorypath}" -type f | while read naslfilename
	do
		printf "$naslfilename,`grep "script_id(" "${naslfilename}" | cut -f 2 -d "(" | cut -f 1 -d ")"`\n"
	done > "${nasldbfilename}"
else
	egrep "${1}" "${nasldbfilename}"
fi
