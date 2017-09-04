#!/bin/sh

DEFPWFILENAME="${1}"
PRIVDEFPWFILENAME="${2}"

tempfilename="$(mktemp -u defpwsplit.XXXXXX)"
cat "${DEFPWFILENAME}" "${PRIVDEFPWFILENAME}" | sort | uniq | sed "s/\/\//\//g" >"${tempfilename}"
for indexcharacter in A B C D E F G H I J K L M N O P Q R S T U V W X Y Z
do
	printf "====== Passwords: %s ======\n" "${indexcharacter}" >"${tempfilename}_${indexcharacter}.txt"
	printf "\n" >>"${tempfilename}_${indexcharacter}.txt"
	printf "^ Vendor Device/Application ^ Access ^ Username ^ Password ^\n" >>"${tempfilename}_${indexcharacter}.txt"
	grep "^| ${indexcharacter}" "${tempfilename}" >>"${tempfilename}_${indexcharacter}.txt"
	printf "\n" >>"${tempfilename}_${indexcharacter}.txt"
	printf "{{tag>Default Passwords}}\n" >>"${tempfilename}_${indexcharacter}.txt"
done
printf "====== Passwords: Other  ======\n" >"${tempfilename}_0.txt"
printf "\n" >>"${tempfilename}_0.txt"
printf "^ Vendor Device/Application ^ Access ^ Username ^ Password ^\n" >>"${tempfilename}_0.txt"
grep -v "^| [A-Z]" "${tempfilename}" >>"${tempfilename}_0.txt"
printf "\n" >>"${tempfilename}_0.txt"
printf "{{tag>Default Passwords}}\n" >>"${tempfilename}_0.txt"
for filename in "${tempfilename}_"?.txt
do
	/usr/share/dokuwiki/bin/dwpage.php -m "Added" commit "${filename}" "passwords:$(printf "%s" "${filename}" | cut -f 2 -d "_" | cut -f 1 -d ".")"
done
rm "${tempfilename}_"?.txt
chown -R www-data:root /var/lib/dokuwiki/data/attic/passwords /var/lib/dokuwiki/data/meta/passwords /var/lib/dokuwiki/data/pages/passwords
