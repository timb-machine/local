#!/bin/sh

FILENAME="${1}"
DISTRIBUTIONNAME="${2}"

packagename="$(printf "%s" "${FILENAME}" | sed "s/\.deb//g")"
packagebasename="$(printf "%s" "${packagename}" | cut -f 1 -d "_")"
packageversion="$(printf "%s" "${packagename}" | cut -f 2 -d "_")"
buildarchitecture="$(dpkg --print-architecture)"
targetarchitecture="$(printf "%s" "${packagename}" | cut -f 3 -d "_")"
changefilename="$(printf "%s" "${packagename}" | sed "s/${targetarchitecture}/${buildarchitecture}/g")"
changeurgency="medium"
packagepriority="$(ar -p "${FILENAME}" control.tar.gz | tar zxvfO - ./control 2>/dev/null | grep "Priority: " | awk '{print $2}')"
emailaddress="$(ar -p "${FILENAME}" control.tar.gz | tar zxvfO - ./control 2>/dev/null | grep "Maintainer: " | awk '{print $2}')"
packagedescription="$(ar -p "${FILENAME}" control.tar.gz | tar zxvfO - ./control 2>/dev/null | grep "Description: " | awk '{print $2}')"
cat | gpg --clearsign --local-user "${emailaddress}" > "${changefilename}.changes" << EOF
Format: 1.8
Date: $(date -R)
Source: ${packagebasename}
Binary: ${packagebasename}
Architecture: ${targetarchitecture}
Version: ${packageversion}
Distribution: ${DISTRIBUTIONNAME}
Urgency: ${changeurgency}
Maintainer: ${emailaddress}
Changed-By: ${emailaddress}
Description:
 ${packagebasename}    - ${packagedescription}
Changes:
 ${packagebasename} (${packageversion}) ${DISTRIBUTIONNAME}; urgency=${changeurgency}
 .
   * Updated
Checksums-Sha1:
 $(sha1sum "${FILENAME}" | cut -f 1 -d " ") $(du -b "${FILENAME}" | tr "\t" " " | cut -f 1 -d " ") ${FILENAME}
Checksums-Sha256:
 $(sha256sum "${FILENAME}" | cut -f 1 -d " ") $(du -b "${FILENAME}" | tr "\t" " " | cut -f 1 -d " ") ${FILENAME}
Files:
 $(md5sum "${FILENAME}" | cut -f 1 -d " ") $(du -b "${FILENAME}" | tr "\t" " " | cut -f 1 -d " ") contrib/admin ${packagepriority} ${FILENAME}
EOF
