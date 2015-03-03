#!/bin/sh

SESSIONNAME="${1}"
MINLENGTH="${2}"
PASSWORDLIST="${3}"
WORDLIST="${4}"
JOHN="${PWD}"

export JOHN
cat /etc/john/john.conf | sed "s/MinLen = ./MinLen = $MINLENGTH/g" >"${JOHN}/john.conf"
cat "$WORDLIST" >"${JOHN}/password.lst"
cat /usr/share/john/password.lst >>"${JOHN}/password.lst"
cat /root/.john/john.pot | cut -f 2 -d ":" >>"${JOHN}/password.lst"
printf "I: admin/single\n"
sudo john -session:"${SESSIONNAME}.1" -users:Administrator,root -single "${PASSWORDLIST}"
printf "I: admin/words\n"
sudo john -session:"${SESSIONNAME}.2" -users:Administrator,root -wordlist:"${JOHN}/password.lst" -rules "${PASSWORDLIST}"
printf "I: shared salts/single\n"
sudo john -session:"${SESSIONNAME}.3" -salts:2 -single "${PASSWORDLIST}"
printf "I: shared salts/wordlist\n"
sudo john -session:"${SESSIONNAME}.4" -salts:2 -wordlist:"${JOHN}/password.lst" -rules "${PASSWORDLIST}"
printf "I: all/wordlist\n"
sudo john -session:"${SESSIONNAME}.5" -wordlist:"${JOHN}/password.lst" -rules "${PASSWORDLIST}"
printf "I: all/incremental\n"
sudo john -session:"${SESSIONNAME}.6" -incremental:All "${PASSWORDLIST}"
