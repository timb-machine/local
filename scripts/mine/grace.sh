#!/bin/sh

BINFILENAME="${1}"
tempfilename="`tempfile`"
echo "set pagination off" > "${tempfilename}"
# | grep ":$" | grep -v "\." | cut -f 2 -d "<" | cut -f 1 -d ">" | cut -f 1 -d "@"
# | grep "@plt" | cut -f 2 -d "<" | cut -f 1 -d "@"
objdump -D "${BINFILENAME}" | grep ":$" | grep -v "\." | cut -f 2 -d "<" | cut -f 1 -d ">" | cut -f 1 -d "@" | sort | uniq | while read line
do
	echo "break ${line}" >> "${tempfilename}"
	echo "commands" >> "${tempfilename}"
	echo "info registers rax rsi rdi rdx rcx" >> "${tempfilename}"
	echo "x/1s \$rax" >> "${tempfilename}"
	echo "x/1s \$rsi" >> "${tempfilename}"
	echo "x/1s \$rdi" >> "${tempfilename}"
	echo "x/1s \$rdx" >> "${tempfilename}"
	echo "x/1s \$rcx" >> "${tempfilename}"
	echo "continue" >> "${tempfilename}"
	echo "end" >> "${tempfilename}"
done
echo "run" >> "${tempfilename}"
gdb -x "${tempfilename}" "${BINFILENAME}"
rm "${tempfilename}"
