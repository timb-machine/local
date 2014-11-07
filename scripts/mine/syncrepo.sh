#!/bin/sh

DIRECTORYPATH="`echo "${1}"`"
REPONAME="${2}"

if [ -z "`echo "${DIRECTORYPATH}" | grep "\/$"`" ]
then
	DIRECTORYPATH="${DIRECTORYPATH}/"
fi
if [ -n "`echo "${REPONAME}" | grep "\/$"`" ]
then
	REPONAME="`echo "${REPONAME}" | sed "s/\/$//g"`"
fi
echo sudo -u www-data rsync -v --progress --partial --recursive "${DIRECTORYPATH}" "rsync://timb@rsync.nth-dimension.org.uk/${REPONAME}"
