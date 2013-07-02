#!/usr/bin/perl
# $Header: /var/lib/cvsd/var/lib/cvsd/local/perl/ike-fuck.pl,v 1.2 2013-07-02 23:09:12 timb Exp $
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
# (c) Tim Brown, 2008
# <mailto:timb@nth-dimension.org.uk>
# <http://www.nth-dimension.org.uk/> / <http://www.machine.org.uk/>
#
# Adapted from Hackin9/Uncon, and ported to Perl.  Additional checks curtesy of
# NTA Monitor wiki <http://www.nta-monitor.com/wiki/index.php/Ike-scan_User_Guide>

use strict;

my $ipaddress = shift;
my $username = shift;

#my @attackmodes = (["--aggressive --id {USERNAME} --pskcrack=psk.txt", "Aggressive User Enum"], ["", "Main"], ["--showbackoff", "Fingerprint"]);
my @attackmodes = (["--aggressive", "Aggressive"], ["", "Main"], ["--showbackoff", "Fingerprint"]);
my @encryptionalgorithms = (["1", "DES"], ["2", "IDEA"], ["3", "Blowfish"], ["4", "RC5"], ["5", "3DES"], ["6", "CAST"], ["7/128", "AES-128"], ["7/196", "AES-196"], ["7/256", "AES-256"], ["8", "Camellia"]);
my @hashalgorithms = (["1", "MD5"], ["2", "SHA1"], ["3", "Tiger"], ["4", "SHA2-256"], ["5", "SHA2-384"], ["6", "SHA2-512"]);
my @authenticationmethods = (["1", "PSK"], ["2", "DSS-Signature"], ["3", "RSA-Signature"], ["4", "RSA-Encryption"], ["5", "Revised-RSA-Encryption"], ["6", "ElGamel-Encryption"], ["7", "Revised-ElGamel-Encryption"], ["8", "ECDSA-Signature"], ["64221", "Hybrid"], ["65001", "XAUTH"]);
# technically we should do 1-20 <http://www.nta-monitor.com/wiki/index.php/Ike-scan_User_Guide#Diffie-Hellman_Group_Values> but that's a bitch
my @diffiehellmangroups = (["1", "MODP-768"], ["2", "MODP-1024"], ["3", "EC2N-155"], ["4", "EC2N-185"], ["5", "MODP-1536"]);

my $attackmode;
my $encryptionalgorithm;
my $hashalgorithm;
my $authenticationmethod;
my $diffiehellmangroup;
my $fullcommand;
my $processhandle;
my $resultstring;

foreach $attackmode (@attackmodes) {
	foreach $encryptionalgorithm (@encryptionalgorithms) {
		foreach $hashalgorithm (@hashalgorithms) {
			foreach $authenticationmethod (@authenticationmethods) {
				foreach $diffiehellmangroup (@diffiehellmangroups) {
					$fullcommand = "ike-scan " . @{$attackmode}[0] . " --trans=" . @{$encryptionalgorithm}[0] . "," . @{$hashalgorithm}[0] . "," . @{$authenticationmethod}[0] . "," . @{$diffiehellmangroup}[0] . " " . $ipaddress;
					$fullcommand =~ s/{USERNAME}/$username/g;
					print "Mode=" . @{$attackmode}[1] . ",Enc=" . @{$encryptionalgorithm}[1]. ",Hash=" . @{$hashalgorithm}[1] . ",Auth=" . @{$authenticationmethod}[1] . ",DH=" . @{$diffiehellmangroup}[1] . "\n";
					open($processhandle, "$fullcommand|");
					$resultstring = "";
					while (<$processhandle>) {
						$resultstring = $resultstring . $_;
					}
					close($processhandle);
					if ($resultstring !~ /.*NO-PROPOSAL-CHOSEN.*/) {
						print $resultstring;
					}
				}
			}
		}
	}
}

