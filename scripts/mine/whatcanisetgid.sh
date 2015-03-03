#!/bin/sh

uid="$(id -u)"
gids="$(id -g) $(id -G)"
for gid in ${gids}
do
	if [ -n "${gidpattern}" ]
	then
		gidpattern="${gidpattern} -o"
	fi
	gidpattern="${gidpattern} ( -group ${gid} -perm -g+x )"
done
find / -type f -perm -g+s -a \( \( -user "${uid}" -a -perm -u+x \) -o \( ${gidpattern} \) -o \( -perm -o+x \) \) -ls 2>/dev/null
