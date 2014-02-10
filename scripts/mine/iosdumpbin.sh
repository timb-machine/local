#!/bin/sh
# TODO functionise the code

# decrypt binary
DYLD_INSERT_LIBRARIES=~/testing/dumpdecrypted/dumpdecrypted.dylib $1
binaryfilename=`basename $1`.decrypted
# hash
find `dirname $1`/.. -type f | while read line
do
	md5sum $line
	sha1sum $line
done | tee $2.hash
# plist
find `dirname $1`/.. -iname "*.plist" | while read line
do
	echo $line
	plutil show $line
done | tee $2.plist
# plist minimum OS
find `dirname $1`/.. -iname "*.plist" | while read line
do
	echo $line
	plutil show $line | grep -i MinimumOS
done | tee $2.plist_minimum_OS
# plist URL handlers
find `dirname $1`/.. -iname "*.plist" | while read line
do
	echo $line
	plutil show $line | grep -i CFBundleURLTypes
done | tee $2.plist_URL_handlers
# sandbox
find `dirname $1`/.. -iname "*.sb" | while read line
do
	echo $line
	cat $line
done | tee $2.sandbox
# entitlements
ldid -e $binaryfilename | tee $2.entitlements
find `dirname $1`/.. -name Entitlements.plist | while read line
do
	echo $line
	plutil show $line
done | tee -a $2.entitlements
# format
otool -f $binaryfilename | tee $2.format
# dependencies
otool -L $binaryfilename | tee $2.dependencies
# load commands
otool -l $binaryfilename | tee $2.load_commands
# bundled libraries
find `dirname $1` -iname "*.dll" | tee $2.bundled_libraries
find `dirname $1` -iname "*.so" | tee -a $2.bundled_libraries
# ARC
otool -Iv $binaryfilename | egrep -i " objc release| objc_autorelease| objc_storeStrong| _objc_retain" | tee $2.ARC
# PIE
otool -hv $binaryfilename | grep -i PIE | tee $2.PIE
# SSP
otool -Iv $binaryfilename | grep -i stack | tee $2.SSP
# class dump
mkdir $2.class_dump
class-dump $binaryfilename -H -o $2.class_dump
# SDL
otool -Iv $binaryfilename | egrep -i "alloca|gets|memcpy|scanf|sprintf|sscanf|strcat|StrCat|strcpy|StrCpy|strlen|StrLen|strncat|StrNCat|strncpy|StrNCpy|strtok|swprintf|vsnprintf|vsprintf|vswprintf|wcscat|wcscpy|wcslen|wcsncat|wcsncpy|wcstok|wmemcpy" | tee $2.SDL
# crypto
otool -Iv $binaryfilename | egrep -i "des|aes|rsa|sha|md5|hash|mac|cbc|ebc|cipher|cert|random|ssl|keychain" | tee $2.crypto
strings $1 | egrep -i "des|aes|rsa|sha|md5|hash|mac|cbc|ebc|cipher|cert|random|ssl|keychain" | tee -a $2.crypto
# file protection
otool -Iv $binaryfilename | egrep -i NSFileProtection | tee $2.file_protection
strings $binaryfilename | egrep -i NSFileProtection | tee -a $2.file_protection
# sql
find `dirname $1`/.. -iname "*.sqlite" | tee $2.sql
otool -Iv $binaryfilename | egrep -i sql | tee -a $2.sql
strings $binaryfilename | egrep -i sql | tee -a $2.sql
# sql query
otool -Iv $binaryfilename | egrep -i "select |insert |update " | tee $2.sql_query
strings $binaryfilename | egrep -i "select |insert |update " | tee -a $2.sql_query
# webview
otool -Iv $binaryfilename | egrep -i webview | tee $2.webview
strings $binaryfilename | egrep -i webview | tee -a $2.webview
# webview javascript
otool -Iv $binaryfilename | egrep -i shouldStartLoadWithRequest | tee $2.webview_javascript
strings $binaryfilename | egrep -i shouldStartLoadWithRequest | tee -a $2.webview_javascript
# webview binary cookies
find `dirname $1`/.. -iname Cookies.binarycookies | tee $2.webview_binary_cookies
# URLs
strings $binaryfilename | egrep "http:\/\/|https:\/\/" | tee $2.URLs
