#!/bin/sh
BINFILENAME="$1"
OUTFILENAME="$2"
# decrypt binary
# UNIMPLEMENTED
# hash
find "`dirname "$BINFILENAME"`/.." -type f | while read line
do
	md5sum $line
	sha1sum $line
done | tee "$OUTFILENAME.hash"
# plist
find "`dirname "$BINFILENAME"`/.." -name "*.plist" | while read line
do
	echo $line
	plutil show $line
done | tee "$OUTFILENAME.plist"
# sandbox
# format
otool -f "$BINFILENAME" | tee "$OUTFILENAME.format"
# dependencies
otool -L "$BINFILENAME" | tee "$OUTFILENAME.dependencies"
# load commands
otool -l "$BINFILENAME" | tee "$OUTFILENAME.load_commands"
# ARC
otool -Iv "$BINFILENAME" | egrep " objc release| objc_autorelease| objc_storeStrong| _objc_retain" | tee "$OUTFILENAME.ARC"
# PIE
otool -hv "$BINFILENAME" | grep PIE | tee "$OUTFILENAME.PIE"
# SSP
otool -Iv "$BINFILENAME" | grep stack | tee "$OUTFILENAME.SSP"
# class dump
mkdir "$OUTFILENAME.class_dump"
class-dump "$BINFILENAME" -H -o "$OUTFILENAME.class_dump"
# SDL
otool -Iv "$BINFILENAME" | egrep "alloca|gets|memcpy|scanf|sprintf|sscanf|strcat|StrCat|strcpy|StrCpy|strlen|StrLen|strncat|StrNCat|strncpy|StrNCpy|strtok|swprintf|vsnprintf|vsprintf|vswprintf|wcscat|wcscpy|wcslen|wcsncat|wcsncpy|wcstok|wmemcpy" | tee "$OUTFILENAME.SDL"
# crypto
otool -Iv "$BINFILENAME" | egrep -i "des|aes|rsa|sha|md5|hash|mac|cbc|ebc|cipher|cert|random|ssl" | tee "$OUTFILENAME.crypto"
strings "$BINFILENAME" | egrep -i "des|aes|rsa|sha|md5|hash|mac|cbc|ebc|cipher|cert|random|ssl" | tee -a "$OUTFILENAME.crypto"
# webview
otool -Iv "$BINFILENAME" | egrep -i "webview" | tee "$OUTFILENAME.webview"
strings "$BINFILENAME" | egrep -i "webview" | tee -a "$OUTFILENAME.webview"
otool -Iv "$BINFILENAME" | egrep -i "shouldStartLoadWithRequest" | tee "$OUTFILENAME.webview"
strings "$BINFILENAME" | egrep -i "shouldStartLoadWithRequest" | tee -a "$OUTFILENAME.webview"
# sql
otool -Iv "$BINFILENAME" | egrep -i "sql" | tee "$OUTFILENAME.sql"
strings "$BINFILENAME" | egrep -i "sql" | tee -a "$OUTFILENAME.sql"
# sql query
otool -Iv "$BINFILENAME" | egrep -i "select |insert |update " | tee "$OUTFILENAME.sql_query"
strings "$BINFILENAME" | egrep -i "select |insert |update " | tee -a "$OUTFILENAME.sql_query"
# URLs
strings "$BINFILENAME" | egrep "http:\/\/|https:\/\/" | tee "$OUTFILENAME.URLs"
# file flags
# UNIMPLEMENTED
