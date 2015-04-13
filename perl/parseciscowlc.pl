#!/usr/bin/perl
# $Revision$
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
# 
# * Redistributions of source code must retain the above copyright notice, this
# list of conditions and the following disclaimer.
# * Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
# * Neither the name of the Nth Dimension nor the names of its contributors may
# be used to endorse or promote products derived from this software without
# specific prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
# (c) Tim Brown, 2015
# <mailto:timb@nth-dimension.org.uk>
# <http://www.nth-dimension.org.uk/> / <http://www.machine.org.uk/>

while (<>) {
	$_ =~ s/\x0a//g;
	$_ =~ s/\x0d//g;
	start:
	# TODO there are doubtless other settings that matter, this is just a start
	if ($_ =~ /^Product Version\.+ (.*)$/) {
		print "running firmware " . $1 . "\n";
	}
	if ($_ =~ /^FIPS prerequisite features\.+ Disabled/) {
		print "no FIPS mode\n";
	}
	if ($_ =~ /^secret obfuscation\.+ Disabled/) {
		print "no secret obfuscation\n";
	}
	if ($_ =~ /^.*case-check \.+ Disabled/) {
		print "no case check\n";
	}
	if ($_ =~ /^.*consecutive-check \.+ Disabled/) {
		print "no consecutive check\n";
	}
	if ($_ =~ /^.*default-check \.+ Disabled/) {
		print "no default check\n";
	}
	if ($_ =~ /^.*username-check \.+ Disabled/) {
		print "no username check\n";
	}
	if ($_ =~ /^Web Mode\.+ Enable/) {
		print "web mode\n";
	}
	if ($_ =~ /^Secure Web Mode\.+ Disable/) {
		print "no secure web mode\n";
	}
	if ($_ =~ /^Secure Web Mode Cipher-Option High\.+ Disable/) {
		print "secure web mode cipher option high disabled\n";
	}
	if ($_ =~ /^Secure Web Mode Cipher-Option SSLv2\.+ Enable/) {
		print "secure web mode sslv2 enabled\n";
	}
	if ($_ =~ /^Secure Shell (ssh)\.+ Disable/) {
		print "no SSH\n";
	}
	if ($_ =~ /^Telnet\.+ Enable/) {
		print "telnet\n";
	}
	if ($_ =~ /^Mgmt Via Wireless Interface\.+ Enable$/) {
		print "wireless interface management\n";
	}
	if ($_ =~ /^Mgmt Via Dynamic Interface\.+ Enable$/) {
		print "dynamic interface management\n";
	}
	if ($_ =~ /^Web Auth Secure Web  \.+ Disable$/) {
		print "forwarding to SSL interface for web based authentication disabled\n";
	}
	if ($_ =~ /^cdp version (.*)$/) {
		print "CDP\n"
	}
	if ($_ =~ /^.*Auto-Immune\.+ Disabled$/) {
		print "no WIPS\n";
	}
	if ($_ =~ /^.*Core Dump is disabled$/) {
		print "no core dumps\n";
	}
	if ($_ =~ /^Rogue on wire Auto-Contain\.+ Disabled$/) {
		print "no rogue AP auto-contain\n";
	}
	if ($_ =~ /^Rogue using our SSID Auto-Contain\.+ Disabled$/) {
		print "no rogue clone AP auto-contain\n";
	}
	if ($_ =~ /^Detect and report Ad-Hoc Networks\.+ Disabled$/) {
		print "no rogue ad-hoc AP reporting\n";
	}
	if ($_ =~ /^Auto-Contain Ad-Hoc Networks\.+ Disabled$/) {
		print "no rogue ad-hoc AP auto-contain\n";
	}
	if ($_ =~ /^Site Name\.+ (.*)$/) {
		print "Site name " . $1 . "\n";
		while (<>) {
			$_ =~ s/\x0a//g;
			$_ =~ s/\x0d//g;
			if ($_ =~ /^.* Network Admission Control .*$/) {
				while (<>) {
					$_ =~ s/\x0a//g;
					$_ =~ s/\x0d//g;
					if ($_ =~ /^.* ([a-z_]+) .* Disabled .*$/) {
						print $1 . " has NAC disabled - this is per interface group, not per AP\n";
					}
					if ($_ =~ /^AP Name/) {
						# TODO this is a bit of a hack, no idea what happens if the order of output is different
						goto start;
					}
				}
			}
		}
	}
	if ($_ =~ /^Cisco AP Name\.+ (.*)$/) {
		# Yay, we have physical tin
		$apname = $1;
		$iosversion = "";
		$sshflag = 1;
		$telnetflag = 1;
		$vlanid = -1;
		while (<>) {
			$_ =~ s/\x0a//g;
			$_ =~ s/\x0d//g;
			# TODO the second if clause is a bit of a hack, no idea what happens if the order of output is different
			if (($_ =~ /^Cisco AP Identifier.*$/) || ($_ =~ /^AP Airewave Director Configuration$/)) {
				print "AP " . $apname . ":";
				print "IOS version " . $iosversion . ":";
				($sshflag == 0) && print "no SSH:";
				($telnetflag == 1) && print "telnet:";
				($vlanid != -1) && print "VLAN " . $vlanid . ":";
				print "\n";
				goto start;
			}
			if ($_ =~ /Mini IOS Version \.+ (.*)$/) {
				$iosversion = $1;
			}
			if ($_ =~ /^Ssh State\.+ Disabled/) {
				$sshflag = 0;
			}
			if ($_ =~ /^Telnet State\.+ Enabled/) {
				$telnetflag = 0;
			}
			if ($_ =~ /Vlan :\.+ (\d+)/) {
				# TODO i need to understand how VLANs (et al) work on the mesh
				$vlanid = $1;
			}
			# TODO there are doubtless other settings that matter, this is just a start
		}
	}
	if ($_ =~ /^Network Name \(SSID\)\.+ (.*)$/) {
		# Yay, we have an AP defined
		$essid = $1;
		$enabledflag = 0;
		$macfilteringflag = 0;
		$broadcastessid = 0;
		$peertopeerflag = 1;
		$localeapflag = 1;
		$openapflag = 0;
		$staticwepflag = 0;
		$dot1xflag = 1;
		$wpaflag = 1;
		$tkipflag = 0;
		$aesflag = 1;
		$dot1xauthflag = 1;
		$pskflag = 0;
		$webflag = 0;
		while (<>) {
			$_ =~ s/\x0a//g;
			$_ =~ s/\x0d//g;
			if (($_ =~ /^WLAN Identifier.*$/) || ($_ =~ /^ACL Configuration$/)) {
				# TODO this is a bit of a hack, no idea what happens if the order of output is different
				if ($enabledflag == 1) {
					# Lets dump some shit
					print "ESSID " . $essid . " enabled:";
					($macfilteringflag == 0) && print "no MAC filtering:";
					($broadcastessid == 1) && print "ESSID broadcast:";
					($peertopeerflag == 1) && print "no link layer segregation:";
					($localeapflag == 0) && print "local eap disabled:";
					($openapflag == 1) && print "open AP:";
					($staticwepflag == 1) && print "static WEP:";
					($dot1xflag == 0) && print "no dot.1X:";
					($wpaflag == 0) && print "no wpaflag/wpaflag2:";
					($tkipflag == 1) && print "tkipflag:";
					($aesflag == 0) && print "no aesflag:";
					($dot1xauthflag == 0) && print "no dot.1X auth:";
					($pskflag == 1) && print "pskflag:";
					($webflag == 1) && print "webflag:";
					print "\n";
				} else {
					print "ESSID " . $essid . " disabled\n";
				}
				goto start;
			}
			if ($_ =~ /^Status\.+ Enabled$/) {
				$enabledflag = 1;
			}
			if ($_ =~ /^MAC Filtering\.+ Enabled$/) {
				$macfilteringflag = 1;
			}
			if ($_ =~ /^Broadcast SSID\.+ Enabled$/) {
				$broadcastessid = 1;
			}
			if ($_ =~ /^Broadcast SSID\.+ Enabled$/) {
				$broadcastessid = 1;
			}
			if ($_ =~ /^Peer-to-Peer Blocking Action\.+ Disabled$/) {
				$peertopeerflag = 0;
			}
			if ($_ =~ /^Local EAP Authentication\.+ Disabled$/) {
				$localeapflag = 0;
			}
			if ($_ =~ /^.*802.11 Authentication:\.+ Open System$/) {
				$openapflag = 1;
			}
			if ($_ =~ /^.*Static WEP Keys\.+ Enabled$/) {
				$staticwepflag = 1;
			}
			if ($_ =~ /^.*802.1X\.+ Disabled$/) {
				$dot1xflag = 0;
			}
			if ($_ =~ /^.*Wi-Fi Protected Access (WPA\/WPA2)\.+ Disabled$/) {
				$wpaflag = 0;
			}
			if ($_ =~ /^.*TKIP Cipher\.+ Enabled$/) {
				$tkipflag = 1;
			}
			if ($_ =~ /^.*AES Cipher\.+ Disabled$/) {
				$aesflag = 0;
			}
			if ($_ =~ /^.*dot.1x\.+ Disabled$/) {
				$dot1xauthflag = 0;
			}
			if ($_ =~ /^.*PSK\.+ Enabled$/) {
				$pskflag = 1;
			}
			if ($_ =~ /^.*Web Based Authentication\.+ Enabled$/) {
				$webflag = 1;
			}
			# TODO there are doubtless other settings that matter, this is just a start
		}
	}
	# TODO there are doubtless other settings that matter, this is just a start
}
