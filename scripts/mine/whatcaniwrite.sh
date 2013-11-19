#!/bin/sh

uid="`id -u`"
gids="`id -g` `id -G`"

for gid in $gids
do
	gidpattern="$gidpattern -o ( -group $gid -perm -g+w )"
done
find / \( ! -type l \) -a \( \( -user "$uid" -a -perm -u+w \) $gidpattern -o \( -perm -o+w \) \) -ls 2> /dev/null
