#!/bin/sh

DIRECTORYPATH="$(printf "%s" "${1}")"
REPONAME="${2}"

if [ -z "$(printf "%s" "${DIRECTORYPATH}" | grep "\/$")" ]
then
	DIRECTORYPATH="${DIRECTORYPATH}/"
fi
if [ -n "$(printf "%s" "${REPONAME}" | grep "\/$")" ]
then
	REPONAME="$(printf "%s" "${REPONAME}" | sed "s/\/$//g")"
fi
sudo -u www-data rsync -v --progress --partial --recursive "${DIRECTORYPATH}" "rsync://timb@rsync.nth-dimension.org.uk/${REPONAME}"
