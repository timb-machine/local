#!/bin/sh

read -s -p "Password: " password
hostname="10.10.10.2"
username="timb"
sharename="timb"
localdirectoryname="/mnt"
remotedirectoryname="/backup"
backupdirectorynames="/etc /usr/local /home /virtual"
mount -o "username=${username},password=${password}" "//${hostname}/${sharename}" "${localdirectoryname}"
if [ -d "${localdirectoryname}${remotedirectoryname}" ]
then
	for backupdirectoryname in ${backupdirectorynames}
	do
		rsync -avz --delete "${backupdirectoryname}" "${localdirectoryname}${remotedirectoryname}/"
	done
	umount "${localdirectoryname}"
fi
