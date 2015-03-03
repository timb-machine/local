#!/bin/sh

cwd="${PWD}"
find . -name "*.class" | while read line
do
	cd "$(dirname "${line}")"
	/usr/local/src/jad/jad -f -i -o -safe "$(basename "${line}")"
	cd "${cwd}"
done
