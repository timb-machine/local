#!/usr/bin/perl -w

use strict;
use File::Basename;
use Parallel::ForkManager;

$ENV{'PATH'} = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

my $filename;
my $commandstring;
my $maximumprocess;
my $producerhandle;
my $filehandle;
my $fullcommandstring;
my $ipaddress;
my $magicdigit;
my $passwordstring;

sub usage {
	die "usage: " . basename($0) . " <commandstring> <filename> <maxiumprocess>";
}

if (@ARGV != 3) {
	usage();
}
$commandstring = shift;
$filename = shift;
$maximumprocess = shift;
if ($commandstring =~ /(.*)/) {
	$commandstring = $1;
} else {
	usage();
}
if (! -f $filename) {
	usage();
}
if ($maximumprocess =~ /([0-9]+)/) {
	$maximumprocess = $1;
} else {
	usage();
}
$producerhandle = Parallel::ForkManager->new($maximumprocess);
open($filehandle, "<" . $filename);
while (defined($ipaddress = <$filehandle>)) {
	$ipaddress =~ s/\x0a//g;
	$ipaddress =~ s/\x0d//g;
	$fullcommandstring = $commandstring;
	$fullcommandstring =~ s/IP/$ipaddress/g;
	$passwordstring = "Ihc!#tP";
	if ($ipaddress =~ /([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)/) {
		$magicdigit = $4;
		$passwordstring =~ s/#/$magicdigit/g;
	}
	$fullcommandstring =~ s/PASSWORD/$passwordstring/g;
	if ($producerhandle->start() == 0) {
		system($fullcommandstring);
		$producerhandle->finish();
	}
	
}
$producerhandle->wait_all_children();
exit(1);
