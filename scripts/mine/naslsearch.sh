#!/bin/sh

SEARCHSTRING="${1}"

naslpluginsdirectorypath="/opt/nessus/lib/nessus/plugins"
nasldbfilename="/usr/local/scripts/mine/naslplugins.txt"
if [ "${SEARCHSTRING}" = "update" -o ! -f "${nasldbfilename}" ]
then
	find "${naslpluginsdirectorypath}" -type f | while read naslfilename
	do
		printf "%s,%s", "$naslfilename" "$(grep "script_id(" "${naslfilename}" | cut -f 2 -d "(" | cut -f 1 -d ")")"
	done >"${nasldbfilename}"
else
	egrep "${SEARCHSTRING}" "${nasldbfilename}"
fi
