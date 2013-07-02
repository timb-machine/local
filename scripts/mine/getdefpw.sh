#!/bin/sh
DEFPWFILENAME="$1"
wget -O - http://www.petefinnigan.com/default/oracle_default_passwords.csv 2>/dev/null | tr -d "\r" | awk 'BEGIN {FS=","} {print "| " toupper($1) " | " toupper(($6 != "") ? $6 : "") (($7 != "") ? $7 : "") (($8 != "") ? $8 : "") (($9 != "") ? $9 : "") " | " $3 " | " $4 " | " }' | sed "s/  / /g" > "$DEFPWFILENAME"
for CHAR in a b c d e f g h i j k l m n o p q r s t u v w x y z 0-9
do
	wget -O - "http://www.defaultpassword.com/?action=dpl&CHAR=$CHAR" 2>/dev/null | grep -v "Manufactor" | grep "VALIGN" | sed "s/TD NOWRAP//g" | cut -f 3,5,11,13,9 -d "<" | sed -e "s/ <//g" -e "s/>/ , /g" | awk 'BEGIN {FS=","} {print "|" toupper($2 $3) "|" toupper($4) "|" $5 "|" $6 "|"}' | sed "s/  / /g"
done >> "$DEFPWFILENAME"
wget -O - http://www.cirt.net/passwords 2>/dev/null | grep "<tr><td>" | cut -f 2 -d "\"" | while read line
do
	wget -O - http://www.cirt.net/passwords$line 2>/dev/null | egrep "Product|Method|User ID|Password&nbsp" | sed -e "s/.*<td align="left" width="100%">//g" -e "s/.*<td align="left" width="85%">//g" -e "s/<\/td>//g" -e "s/<\/tr>//g" | while read PRODUCT
	do
		read METHOD
		read USERNAME
		read PASSWORD
		PRODUCT="`echo $PRODUCT | tr "[a-z]" "[A-Z]"`"
		METHOD="`echo "$METHOD" | tr "[a-z]" "[A-Z]"`"
		echo "| $PRODUCT | $METHOD | $USERNAME | $PASSWORD |" | sed "s/  / /g"
	done
done >> "$DEFPWFILENAME"
wget -O - http://www.routerpasswords.com/index.asp 2>/dev/null | tr ">" "\n" | grep "<option" | sed -e "s/<option value=\"//g" -e "s/\"//g" | while read VENDOR
do
	wget --post-data "router=$VENDOR&findpass=1" -O - http://www.routerpasswords.com/index.asp 2>/dev/null | grep "<td width=\"100\">" | grep "<font face=\"Arial\" size=\"2\">" | sed -e "s/.*<font face=\"Arial\" size=\"2\">//g" -e "s/<\/font>//g" -e "s/<\/b>//g" -e "s/<\/td>//g" -e "s/<i>//g" -e "s/<\/i>//g" | tr -d "\r" | while read VENDOR
	do
		read MODEL
		read METHOD
		read USERNAME
		read PASSWORD
		PRODUCT="`echo "$VENDOR $MODEL" | tr "[a-z]" "[A-Z]"`"
		METHOD="`echo "$METHOD" | tr "[a-z]" "[A-Z]"`"
		echo "| $PRODUCT | $METHOD | $USERNAME | $PASSWORD |" | sed "s/  / /g"
	done
done >> "$DEFPWFILENAME"
for page in `seq 1 50`
do
	wget -O - "http://www.phenoelit-us.org/dpl/index.php?page=$page&sVENDOR=&sMODEL=&sVERSION=&perpage=50" 2>/dev/null | grep "<td>" | egrep -v "<b|<input|Vendor:|Model:|Version:|Access Type:|Username:|Password:|Privileges:|Notes:|Entries" | sed -e "s/.*<td>//g" -e "s/<\/td>.*//g" | while read VENDOR
	do
		read MODEL
		read VERSION
		read METHOD
		read USERNAME
		read PASSWORD
		read PRIVILEGES
		read NOTES
		PRODUCT="`echo "$VENDOR $MODEL" | tr "[a-z]" "[A-Z]"`"
		METHOD="`echo "$METHOD" | tr "[a-z]" "[A-Z]"`"
		echo "| $PRODUCT | $METHOD | $USERNAME | $PASSWORD |" | sed "s/  / /g"
	done
done >> "$DEFPWFILENAME"
