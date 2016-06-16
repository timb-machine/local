#!/bin/sh
# egrep "Depends|Recommends" control | cut -f 2- -d: | cut -f 2- -d, | tr "," "\n" | tr -d " " | grep -v "^security-"

REPONAME="${1}"

while read packagename
do
	if [ "$(wget -O - "https://packages.debian.org/search?keywords=${packagename}&searchon=names&suite=${REPONAME}&section=all" | grep "Sorry, your search gave no results")" = "" ]
	then
		echo "${packagename}" >> "${REPONAME}";
	else
		echo "${packagename}" >> "could_not_find_${REPONAME}"
	fi
done
