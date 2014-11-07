#!/bin/sh

RELEASENAME="${1}"
ZONE="${2}"
VMNAME="${3}"
RAM="${4}"
DISK="${5}"

mkdir "/virtual/kvm/${VMNAME}"
chgrp libvirt "/virtual/kvm/${VMNAME}"
chmod g+ws "/virtual/kvm/${VMNAME}"
qemu-img create -f qcow2 "/virtual/kvm/${VMNAME}/${VMNAME}.img" "${DISK}G"
case "${ZONE}" in
	trusted)
		virt-install --connect "qemu:///system" --virt-type "kvm" --name "${VMNAME}" --ram "${RAM}" --graphics "vnc" --video "vmvga" --vcpus 1 --cpu host-model-only --disk "/virtual/kvm/${VMNAME}/${VMNAME}.img,format=qcow2" --location "http://ftp.debian.org/debian/dists/${1}/main/installer-amd64/" --os-type "linux" --os-variant "debianwheezy" --hvm --network "bridge:nat" --network "bridge:${ZONE}" --extra-args "auto=true url=http://192.168.255.1:3142/src/${RELEASENAME}.preseed hostname=${VMNAME} domain=${ZONE}.tmb netcfg/choose_interface=eth0"
		;;
esac
