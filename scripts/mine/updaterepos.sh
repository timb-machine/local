#!/bin/sh
DIRNAME="$1"
cwd="$PWD"
find "$DIRNAME" -name *-trunk -type d | while read line
do
	echo "I: `basename $line`"
	if [ -d $line/.git ]
	then
		cd $line
		git pull
		cd $cwd
	fi
	if [ -d $line/.svn ]
	then
		cd $line
		svn update
		cd $cwd
	fi
	if [ -d $line/.hg ]
	then
		cd $line
		hg pull
		cd $cwd
	fi
	if [ -d $line/CVS ]
	then
		cd $line
		cvs update
		cd $cwd
	fi
done
