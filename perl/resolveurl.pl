#!/usr/bin/perl

use strict;
use LWP;

$ENV{'PATH'} = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

my $url;
my $redirectflag;
my $httphandle;
my $requesthandle;
my $responsehandle;

sub usage {
        die "usage: " . basename($0) . " <url>";
}

if (@ARGV != 1) {
        usage();
}
$url = shift;
$httphandle = LWP::UserAgent->new(max_redirect => 0);
$httphandle->agent("Mozilla/5.0 (compatible; resolveurl.pl 0.1)");
$redirectflag = 1;
while ($redirectflag == 1) {
	$redirectflag = 0;
	$requesthandle = HTTP::Request->new(HEAD => $url);
	$responsehandle = $httphandle->request($requesthandle);
	if ($responsehandle->is_redirect) {
		$url = $responsehandle->header("location");
		print $url . "\n";
		$redirectflag = 1;
	}
}
