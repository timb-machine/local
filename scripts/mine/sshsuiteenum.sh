#!/bin/sh

IPADDRESS="${1}"

for protocolversion in 1 2
do
	for ciphername in 3des blowfish des 3des-cbc aes128-cbc aes192-cbc aes256-cbc aes128-ctr aes192-ctr aes256-ctr arcfour128 arcfour256 arcfour blowfish-cbc cast128-cbc twofish cast chacha20-poly1305@openssh.com aes128-gcm@openssh.com aes256-gcm@openssh.com
	do
		for macname in hmac-md5 hmac-sha1 hmac-ripemd160 hmac-sha1-96 hmac-md5-96 hmac-ripemd160-96 hmac-sha2-256 hmac-sha2-512 umac-64@openssh.com umac-128@openssh.com hmac-md5-etm@openssh.com hmac-md5-96-etm@openssh.com hmac-ripemd160-etm@openssh.com hmac-sha1-etm@openssh.com hmac-sha1-96-etm@openssh.com hmac-sha2-256-etm@openssh.com hmac-sha2-512-etm@openssh.com umac-64-etm@openssh.com umac-128-etm@openssh.com
		do
			for compressionflag in yes no
			do
				responsestring="$(ssh "-${protocolversion}" -c "${ciphername}" -m "${macname}" -o "Compression \"${compressionflag}\"" -o "PubkeyAuthentication \"no\"" -o "NumberOfPasswordprompts 0" -o "UserKnownHostsFile \"/dev/null\"" -o "StrictHostKeyChecking no" "${IPADDRESS}" 2>&1)"
				case "${responsestring}" in
					*No?valid?ciphers*)
						printf "E: Invalid cipher: %s\n" $ciphername
						;;
					*Unknown?mac?type*)
						printf "E: Invalid MAC: %s\n" $macname
						;;
					*Permission?denied*)
						printf "I: %s:%s:%s:%s:enabled\n" "${protocolversion}" "${ciphername}" "${macname}" "${compressionflag}"
						;;
				esac
			done
		done
	done
done
