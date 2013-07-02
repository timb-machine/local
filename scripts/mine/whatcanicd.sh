#!/bin/sh

uid="`id -u`"
gids="`id -g` `id -G`"

for gid in $gids
do
	gidpattern="$gidpattern -o ( -group $gid -perm -g+x )"
done
find / \( -type d \) -a \( \( -user "$uid" -a -perm -u+x \) $gidpattern -o \( -perm -o+x \) \) -ls 2>/dev/null
