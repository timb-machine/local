#!/bin/sh
NFSHOSTNAME="$1"
showmount -e "$1" | grep -v Export | while read sharepathname acl
do
	mkdir /mnt/$NFSHOSTNAME
	if [ "`echo $acl | grep anon`" != "" -o "`echo $acl | grep 0.0.0.0`" != "" -o "$acl" = "*" -o "$acl" = "(everyone)" ]
	then
		echo "E: $NFSHOSTNAME:$sharepathname accessible from any host"
	else
		echo "I: $NFSHOSTNAME:$sharepathname accessible from $acl"
		ifconfig -a | grep "inet addr" | awk '{print $2}' | cut -f 2 -d ":" | cut -f 1-3 -d "." | while read myipaddress
		do
			if [ "`echo $acl | grep $myipaddress`" != "" ]
			then
				echo "W: $NFSHOSTNAME:$sharepathname accessible from local subnet $myipaddress"
			fi
		done
	fi
	mount -t nfs4 -o intr,tcp,sec=krb5 $NFSHOSTNAME:$sharepathname /mnt/$NFSHOSTNAME
	if [ "`mount | grep "/mnt/$NFSHOSTNAME"`" != "" ]
	then
		find /mnt/$NFSHOSTNAME -type d -perm -o+w 2> /dev/null | sed "s/\/mnt\/$NFSHOSTNAME//g" | while read directorypath
		do
			echo "W: $NFSHOSTNAME:$sharepathname$directorypath may be world writable"
			tempfilename="`mktemp -u --tmpdir="/mnt/$NFSHOSTNAME$directorypath/" auditnfs.dw.XXXXXX 2>&1 | grep -v "Permission"`"
			if [ "$tempfilename" != "" ]
			then
				touch "$tempfilename" 2> /dev/null
				if [ -f "$tempfilename" ]
				then
					asid="`ls -la $tempfilename | awk '{print $3 ":" $4}'`"
					rm -i "$tempfilename"
					echo "E: $NFSHOSTNAME:$sharepathname$directorypath is world writable as $asid"
				fi
			fi
		done
		find /mnt/$NFSHOSTNAME -type d -perm -g+w 2> /dev/null | sed "s/\/mnt\/$NFSHOSTNAME//g" | while read directorypath
		do
			groupid="`ls -ld /mnt/$NFSHOSTNAME$directorypath | awk '{print $4}'`"
			echo "W: $NFSHOSTNAME:$sharepathname$directorypath may be group writable by $groupid"
			tempfilename="`mktemp -u --tmpdir="/mnt/$NFSHOSTNAME$directorypath/" auditnfs.dg.XXXXXX 2>&1 | grep -v "Permission"`"
			/usr/local/src/become/become -r 65533:$groupid "touch $tempfilename" > /dev/null 2>&1
			if [ "$tempfilename" != "" ]
			then
				if [ -f "$tempfilename" ]
				then
					asid="`ls -la $tempfilename | awk '{print $3 ":" $4}'`"
					/usr/local/src/become/become -r 65533:$groupid "rm -i $tempfilename" > /dev/null 2>&1
					echo "E: $NFSHOSTNAME:$sharepathname$directorypath is group writable by $groupid as $asid"
				fi
			fi
		done
		find /mnt/$NFSHOSTNAME -type d -perm -u+w 2> /dev/null | sed "s/\/mnt\/$NFSHOSTNAME//g" | while read directorypath
		do
			userid="`ls -ld /mnt/$NFSHOSTNAME$directorypath | awk '{print $3}'`"
			echo "W: $NFSHOSTNAME:$sharepathname$directorypath may be user writable by $userid"
			tempfilename="`mktemp -u --tmpdir="/mnt/$NFSHOSTNAME$directorypath/" auditnfs.du.XXXXXX 2>&1 | grep -v "Permission"`"
			if [ "$tempfilename" != "" ]
			then
				/usr/local/src/become/become -r $userid:65533 "touch $tempfilename" > /dev/null 2>&1
				if [ -f "$tempfilename" ]
				then
					asid="`ls -la $tempfilename | awk '{print $3 ":" $4}'`"
					/usr/local/src/become/become -r 65533:$groupid "chmod u+xs $tempfilename" > /dev/null 2>&1
					echo "E: $NFSHOSTNAME:$sharepathname$directorypath is user writable by $userid as $asid"
				fi
			fi
		done
		find /mnt/$NFSHOSTNAME -type f -perm -o+w 2> /dev/null | sed "s/\/mnt\/$NFSHOSTNAME//g" | while read filename
		do
			echo "W: $NFSHOSTNAME:$sharepathname$filename may be world writable"
		done
		find /mnt/$NFSHOSTNAME -type f -perm -g+w 2> /dev/null | sed "s/\/mnt\/$NFSHOSTNAME//g" | while read filename
		do
			groupid="`ls -ld /mnt/$NFSHOSTNAME$filename | awk '{print $4}'`"
			echo "W: $NFSHOSTNAME:$sharepathname$filename may be group writable by $groupid"
		done
		find /mnt/$NFSHOSTNAME -type f -perm -u+w 2> /dev/null | sed "s/\/mnt\/$NFSHOSTNAME//g" | while read filename
		do
			userid="`ls -ld /mnt/$NFSHOSTNAME$filename | awk '{print $3}'`"
			echo "W: $NFSHOSTNAME:$sharepathname$filename may be user writable by $userid"
		done
		find /mnt/$NFSHOSTNAME -type f -perm -o+r \( -name shadow -o -name passwd -name hosts.equiv -o -name shosts.equiv -o -name id_dsa -o -name id_rsa -o -name .rhosts -o -name .shosts \) 2> /dev/null | sed "s/\/mnt\/$NFSHOSTNAME//g" | while read filename
		do
			echo "W: $NFSHOSTNAME:$sharepathname$filename is world readable"
		done
		find /mnt/$NFSHOSTNAME -type f -perm -g+r \( -name shadow -o -name passwd -name hosts.equiv -o -name shosts.equiv -o -name id_dsa -o -name id_rsa -o -name .rhosts -o -name .shosts \) 2> /dev/null | sed "s/\/mnt\/$NFSHOSTNAME//g" | while read filename
		do
			groupid="`ls -ld /mnt/$NFSHOSTNAME$filename | awk '{print $4}'`"
			echo "W: $NFSHOSTNAME:$sharepathname$filename is group readable by $groupid"
		done
		find /mnt/$NFSHOSTNAME -type f -perm -u+r \( -name shadow -o -name passwd -name hosts.equiv -o -name shosts.equiv -o -name id_dsa -o -name id_rsa -o -name .rhosts -o -name .shosts \) 2> /dev/null | sed "s/\/mnt\/$NFSHOSTNAME//g" | while read filename
		do
			userid="`ls -ld /mnt/$NFSHOSTNAME$filename | awk '{print $3}'`"
			echo "W: $NFSHOSTNAME:$sharepathname$filename is user readable by $userid"
		done
		umount /mnt/$NFSHOSTNAME
	fi
	rmdir /mnt/$NFSHOSTNAME
done
echo "I: I wonder what it's mounted as on the server side, nodev, setuid???"
echo "I: You could also try hardlinking other files on the same partition in?"
