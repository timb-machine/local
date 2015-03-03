#!/bin/sh

BINFILENAME="${1}"

tempfilename="$(tempfile)"
printf "set pagination off" >"${tempfilename}"
# | grep ":$" | grep -v "\." | cut -f 2 -d "<" | cut -f 1 -d ">" | cut -f 1 -d "@"
# | grep "@plt" | cut -f 2 -d "<" | cut -f 1 -d "@"
objdump -D "${BINFILENAME}" | grep ":$" | grep -v "\." | cut -f 2 -d "<" | cut -f 1 -d ">" | cut -f 1 -d "@" | sort | uniq | while read line
do
	printf "break %s\n", "${line}" >>"${tempfilename}"
	printf "commands\n" >>"${tempfilename}"
	printf "info registers rax rsi rdi rdx rcx\n" >>"${tempfilename}"
	printf "x/1s \$rax\n" >>"${tempfilename}"
	printf "x/1s \$rsi\n" >>"${tempfilename}"
	printf "x/1s \$rdi\n" >>"${tempfilename}"
	printf "x/1s \$rdx\n" >>"${tempfilename}"
	printf "x/1s \$rcx\n" >>"${tempfilename}"
	printf "continue\n" >>"${tempfilename}"
	printf "end\n" >>"${tempfilename}"
done
printf "run\n" >>"${tempfilename}"
gdb -x "${tempfilename}" "${BINFILENAME}"
rm "${tempfilename}"
