#!/bin/sh
DIRNAME="$1"
find "$DIRNAME" ! \( -perm -u+s -o -perm -g+s \) ! \( -perm -g+w \) -exec chown root:staff {} \;
chmod -R u+rw,g+rw,o+r-w "$DIRNAME"
find "$DIRNAME" -type d -exec chmod u+x,g+xs,o+x {} \;
find "$DIRNAME" -type f -perm -u+x -exec chmod u+x,g+x,o+x {} \; 
