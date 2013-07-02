#!/bin/sh

pwd=$PWD
find . -name "*.class" | while read line
do
	cd `dirname $line`
	/usr/local/src/jad/jad -f -i -o -safe `basename $line`
	cd $pwd
done
