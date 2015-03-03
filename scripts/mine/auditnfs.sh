#!/bin/sh

NFSHOSTNAME="${1}"

showmount -e "${NFSHOSTNAME}" | grep -v Export | while read sharepathname acl
do
	mkdir "/mnt/${NFSHOSTNAME}"
	if [ "$(printf "%s" "${acl}" | grep anon)" != "" -o "$(printf "%s" "${acl}" | grep 0.0.0.0)" != "" -o "${acl}" = "*" -o "${acl}" = "(everyone)" ]
	then
		printf "E: %s:%s accessible from any host\n" "${NFSHOSTNAME}" "${sharepathname}"
	else
		printf "I: %s:%s accessible from %s\n" "${NFSHOSTNAME}" "${sharepathname}" "${acl}"
		ifconfig -a | grep "inet addr" | awk '{print $2}' | cut -f 2 -d ":" | cut -f 1-3 -d "." | while read myipaddress
		do
			if [ "$(printf "%s" "${acl}" | grep "${myipaddress}")" != "" ]
			then
				printf "W: %s:%s accessible from local subnet %s\n" "${NFSHOSTNAME}" "${sharepathname}" "${myipaddress}"
			fi
		done
	fi
	mount -t nfs4 -o intr,tcp,sec=krb5 "${NFSHOSTNAME}:${sharepathname}" "/mnt/${NFSHOSTNAME}"
	if [ "$(mount | grep "/mnt/${NFSHOSTNAME}")" != "" ]
	then
		find "/mnt/${NFSHOSTNAME}" -type d -perm -o+w 2> /dev/null | sed "s/\/mnt\/${NFSHOSTNAME}//g" | while read directorypath
		do
			printf "W: %s:%s may be world writable\n" "${NFSHOSTNAME}" "${sharepathname}${directorypath}"
			tempfilename="$(mktemp -u --tmpdir="/mnt/${NFSHOSTNAME}${directorypath}/" auditnfs.dw.XXXXXX 2>&1 | grep -v "Permission")"
			if [ "${tempfilename}" != "" ]
			then
				touch "${tempfilename}" 2> /dev/null
				if [ -f "${tempfilename}" ]
				then
					asid="$(ls -la "${tempfilename}" | awk '{print $3 ":" $4}')"
					rm -i "${tempfilename}"
					printf "E: %s:%s%s is world writable as %s\n" "${NFSHOSTNAME}" "${sharepathname}" "${directorypath}" "${asid}"
				fi
			fi
		done
		find "/mnt/${NFSHOSTNAME}" -type d -perm -g+w 2> /dev/null | sed "s/\/mnt\/${NFSHOSTNAME}//g" | while read directorypath
		do
			gid="$(ls -ld "/mnt/${NFSHOSTNAME}${directorypath}" | awk '{print $4}')"
			printf "W: %s:%s%s may be group writable by %s\n" "${NFSHOSTNAME}" "${sharepathname}" "${directorypath}" "%{gid}"
			tempfilename="$(mktemp -u --tmpdir="/mnt/${NFSHOSTNAME}${directorypath}/" auditnfs.dg.XXXXXX 2>&1 | grep -v "Permission")"
			/usr/local/src/become/become -r "65533:${gid}" "touch \"$tempfilename\"" >/dev/null 2>&1
			if [ "${tempfilename}" != "" ]
			then
				true
				if [ -f "${tempfilename}" ]
				then
					true
					asid="$(ls -la "${tempfilename}" | awk '{print $3 ":" $4}')"
					/usr/local/src/become/become -r "65533:${gid}" "rm -i \"${tempfilename}\"" > /dev/null 2>&1
					printf "E: %s:%s%s is group writable by %s as %s\n" "${NFSHOSTNAME}" "${sharepathname}" "${directorypath}" "${gid}" "${asid}"
				fi
			fi
		done
		find "/mnt/${NFSHOSTNAME}" -type d -perm -u+w 2> /dev/null | sed "s/\/mnt\/${NFSHOSTNAME}//g" | while read directorypath
		do
			uid="$(ls -ld "/mnt/${NFSHOSTNAME}${directorypath}" | awk '{print $3}')"
			printf "W: %s:%s%s may be user writable by %s\n" "${NFSHOSTNAME}" "${sharepathname}" "${directorypath}" "${uid}"
			tempfilename="$(mktemp -u --tmpdir="/mnt/${NFSHOSTNAME}$directorypath/" auditnfs.du.XXXXXX 2>&1 | grep -v "Permission")"
			if [ "$tempfilename" != "" ]
			then
				/usr/local/src/become/become -r "${uid}:65533" "touch \"${tempfilename}\"" >/dev/null 2>&1
				if [ -f "${tempfilename}" ]
				then
					asid="$(ls -la "${tempfilename}" | awk '{print $3 ":" $4}')"
					/usr/local/src/become/become -r "65533:${gid}" "chmod u+xs \"${tempfilename}\"" > /dev/null 2>&1
					printf "E: %s:%s%s is user writable by %s as %s\n" "${NFSHOSTNAME}" "${sharepathname}" "${directorypath}" "${uid}" "${asid}"
				fi
			fi
		done
		find "/mnt/${NFSHOSTNAME}" -type f -perm -o+w 2>/dev/null | sed "s/\/mnt\/${NFSHOSTNAME}//g" | while read filename
		do
			printf "W: %s:%s%s may be world writable\n" "${NFSHOSTNAME}" "${sharepathname}" "${filename}"
		done
		find "/mnt/${NFSHOSTNAME}" -type f -perm -g+w 2>/dev/null | sed "s/\/mnt\/${NFSHOSTNAME}//g" | while read filename
		do
			gid="$(ls -ld "/mnt/${NFSHOSTNAME}${filename}" | awk '{print $4}')"
			printf "W: %s:%s:%s may be group writable by %s\n" "${NFSHOSTNAME}" "${sharepathname}" "${filename}" "${gid}"
		done
		find "/mnt/${NFSHOSTNAME}" -type f -perm -u+w 2> /dev/null | sed "s/\/mnt\/${NFSHOSTNAME}//g" | while read filename
		do
			uid="$(ls -ld "/mnt/${NFSHOSTNAME}${filename}" | awk '{print $3}')"
			printf "W: %s:%s%s may be user writable by %s\n" "${NFSHOSTNAME}" "${sharepathname}" "${filename}" "${uid}"
		done
		find "/mnt/${NFSHOSTNAME}" -type f -perm -o+r \( -name shadow -o -name passwd -name hosts.equiv -o -name shosts.equiv -o -name id_dsa -o -name id_rsa -o -name .rhosts -o -name .shosts \) 2> /dev/null | sed "s/\/mnt\/${NFSHOSTNAME}//g" | while read filename
		do
			printf "W: %s%s%s is world readable by %s\n" "${NFSHOSTNAME}" "${sharepathname}" "${filename}"
		done
		find /mnt/${NFSHOSTNAME} -type f -perm -g+r \( -name shadow -o -name passwd -name hosts.equiv -o -name shosts.equiv -o -name id_dsa -o -name id_rsa -o -name .rhosts -o -name .shosts \) 2> /dev/null | sed "s/\/mnt\/${NFSHOSTNAME}//g" | while read filename
		do
			gid="$(ls -ld "/mnt/${NFSHOSTNAME}${filename}" | awk '{print $4}')"
			printf "W: %s%s%s is group readable by %s\n" "${NFSHOSTNAME}" "${sharepathname}" "${filename}" "${gid}"
		done
		find /mnt/${NFSHOSTNAME} -type f -perm -u+r \( -name shadow -o -name passwd -name hosts.equiv -o -name shosts.equiv -o -name id_dsa -o -name id_rsa -o -name .rhosts -o -name .shosts \) 2> /dev/null | sed "s/\/mnt\/${NFSHOSTNAME}//g" | while read filename
		do
			uid="$(ls -ld "/mnt/${NFSHOSTNAME}${filename}" | awk '{print $3}')"
			printf "W: %s%s%s is user readable by %s\n" "${NFSHOSTNAME}" "${sharepathname}" "${filename}" "${uid}"
		done
		umount "/mnt/${NFSHOSTNAME}"
	fi
	rmdir "/mnt/${NFSHOSTNAME}"
done
printf "I: I wonder what it's mounted as on the server side, nodev, setuid???\n"
printf "I: You could also try hardlinking other files on the same partition in?\n"
