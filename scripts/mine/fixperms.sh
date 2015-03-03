#!/bin/sh

DIRECTORYPATH="${1}"

find "${DIRECTORYPATH}" ! \( -perm -u+s -o -perm -g+s \) ! \( -perm -g+w \) -exec chown root:staff {} \;
chmod -R u+rw,g+rw,o+r-w "${DIRECTORYPATH}"
find "${DIRECTORYPATH}" -type d -exec chmod u+x,g+xs,o+x {} \;
find "${DIRECTORYPATH}" -type f -perm -u+x -exec chmod u+x,g+x,o+x {} \; 
