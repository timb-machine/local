#!/usr/bin/perl

use File::Basename;
use Crypt::Password;

sub usage {
	die "usage: " . basename($0) . " <cryptotextstring>";
}

if (@ARGV != 1) {
        usage();
}
$cryptotextstring = shift;
if (!defined($cryptotextstring)) {
}

($dummystring, $cryptoflag, $saltstring, $passwordstring) = split(/\$/, $cryptotextstring);
if ($cryptoflag == "5") {
	$cryptoflag = "sha256";
} else {
	if ($cryptoflag eq "6") {
		$cryptoflag = "sha512";
	} else {
		die "E: Not supported";
	}
}

while ($plaintextstring = <>) {
	$plaintextstring =~ s/\x0a//g;
	$plaintextstring =~ s/\x0d//g;
	$passwordhandle = Crypt::Password->new($plaintextstring, $saltstring, $cryptoflag);
	($dummystring, $crypto2flag, $salt2string, $password2string) = split(/\$/, $passwordhandle->crypted());
	if ($password2string eq $passwordstring) {
		print "I: " . $plaintextstring . "\n";
		exit(2);
	}
}
exit(1);
