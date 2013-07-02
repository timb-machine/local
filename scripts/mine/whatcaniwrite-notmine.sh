#!/bin/sh

uid="`id -u`"
gids="`id -g` `id -G`"

for gid in $gids
do
	if [ -n "$gidpattern" ]
	then
		gidpattern="$gidpattern -o"
	fi
	gidpattern="$gidpattern ( -group $gid -perm -g+w )"
done
find / \( ! -type l \) -a \( ! -user "$uid" \) -a \( $gidpattern -o \( -perm -o+w \) \) -ls 2>/dev/null
