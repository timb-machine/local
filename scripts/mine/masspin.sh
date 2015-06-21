#!/bin/sh

while read packagename
do
	apt-cache show "${packagename}" | grep Depends | sed "s/Depends: //" | tr "," "\n" | tr -d "()" | sed "s/^ //g" | while read dependentpackagename _
	do
		version="$(apt-cache policy "${dependentpackagename}" | grep Installed | awk '{print $2}')"
		echo "Package: ${dependentpackagename}" > "/etc/apt/preferences.d/${dependentpackagename}"
		echo "Pin: version ${version}" >> "/etc/apt/preferences.d/${dependentpackagename}"
		echo "Pin-Priority: 1001" >> "/etc/apt/preferences.d/${dependentpackagename}"
	done
done
