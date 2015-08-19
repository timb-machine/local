#!/bin/sh

FILENAME="${1}"

apt-cache showsrc "$(dpkg -S "${FILENAME}" | cut -f 1 -d ":")" | grep "Vcs-Browser" | cut -f 2- -d " " | sort | uniq
