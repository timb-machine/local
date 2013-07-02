#!/bin/sh
DEFPWFILENAME="$1"
PRIVDEFPWFILENAME="$2"
tempfilename="`tempfile`"
cat "$DEFPWFILENAME" "$PRIVDEFPWFILENAME" | sort | uniq | sed "s/\/\//\//g" > "$tempfilename"
for char in A B C D E F G H I J K L M N O P Q R S T U V W X Y Z
do
	echo "====== Passwords: ${char} ======" > "$tempfilename_$char.txt"
	echo "" >> "$tempfilename_$char.txt"
	echo "^ Vendor Device/Application ^ Access ^ Username ^ Password ^" >> "$tempfilename_$char.txt"
	grep "^| $char" $tempfilename >> "$tempfilename_$char.txt"
	echo "" >> "$tempfilename_$char.txt"
	echo "{{tag>Default Passwords}}" >> "$tempfilename_$char.txt"
done
echo "====== Passwords: Other  ======" > "$tempfilename_0.txt"
echo "" >> "$tempfilename_0.txt"
echo "^ Vendor Device/Application ^ Access ^ Username ^ Password ^" >> "$tempfilename_0.txt"
grep -v "^| [A-Z]" "$tempfilename" >> "$tempfilename_0.txt"
echo "" >> "$tempfilename_0.txt"
echo echo "{{tag>Default Passwords}}" >> "$tempfilename_0.txt"
for filename in "$tempfilename_"?.txt
do
	/usr/share/dokuwiki/bin/dwpage.php -m "Added" commit "$filename" "passwords:`echo $filename | cut -f 2 -d "_" | cut -f 1 -d "."`"
done
rm "$tempfilename_"?.txt
chown -R www-data:root /var/lib/dokuwiki/data/attic/passwords /var/lib/dokuwiki/data/meta/passwords /var/lib/dokuwiki/data/pages/passwords
