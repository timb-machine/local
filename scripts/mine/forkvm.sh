#!/bin/sh

BACKINGVMNAME="${1}"
ZONE="${2}"
VMNAME="${3}"
RAM="${4}"

mkdir "/virtual/kvm/${VMNAME}"
chgrp libvirt "/virtual/kvm/${VMNAME}"
chmod g+ws "/virtual/kvm/${VMNAME}"
qemu-img create -f qcow2 -b "/virtual/kvm/${BACKINGVMNAME}/${BACKINGVMNAME}.img" "/virtual/kvm/${VMNAME}/${VMNAME}.img"
virt-install --connect "qemu:///system" --virt-type "kvm" --import --name "${VMNAME}" --ram "${RAM}" --graphics "vnc" --video "vmvga" --vcpus 1 --cpu host-model-only --disk "/virtual/kvm/${VMNAME}/${VMNAME}.img,format=qcow2" --hvm --network "bridge:${ZONE}" --noautoconsole
