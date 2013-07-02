#!/usr/bin/perl -w
#
# $Id: webtime.pl,v 1.1.1.1 2013-07-02 23:05:57 timb Exp $
# 
# Sript to grab the time from a web server, compare it to the local
# time and print out the difference.  Has 2 uses:
#
# 1: Finds if the web server clock is accurate (assuming your local
#    clock is)
#
# 2: Finds if web server is load balanced (assuming all web clocks are
#    not synchronised with each other)
#
# Grab LWP and Data::Manip modules from CPAN with the following
# command if they're not available in the distro you're using:
#
# # perl -MCPAN -e shell
# install LWP
# install Date::Manip
#
# Time sync your clock before running:
# $ ntpdate ntp.demon.co.uk
#
# Change Log
# ----------
# $Log: not supported by cvs2svn $
# Revision 1.3  2005/11/15 10:10:38  ml
# Bug fix: Now error for HTTP as well has HTTPS when server is unreachable.
#
# Revision 1.2  2005/11/15 10:04:28  ml
# Bug fix: Now fails with an error if it can't connect to remote host
# Also added CVS vars to head for change log and version.
# Version is printed in help message.
#

use strict;
use LWP;
use Date::Manip;

my $version = '$Id: webtime.pl,v 1.1.1.1 2013-07-02 23:05:57 timb Exp $';
my $usage = "Usage: $0 url [count]

Determines if a web server's clock is accurate

$version\n";
my $url = shift or die $usage;
my $iterations = shift || 10;

# Set up user agent object
my $ua = LWP::UserAgent->new;
$ua->agent('Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.7.10) Gecko/20050906 Firefox/1.0.6');

# Create HTTP request object
my $request = HTTP::Request->new(GET => $url);

foreach my $count (1..$iterations) {
	# Get client time
	my $client_date = scalar(localtime);
	my $client_date_dm = ParseDate($client_date);

	# Get server time
	my $response = $ua->request($request);
	my ($server_date) = $response->as_string =~ /Date: ([^\n]*)\n/s;

	# Check if we got a connection refused
	if ($response->code eq "500") {
		# HTTP and HTTPS give different internal LWP error messages, hence the horrible regexp.
		if ($response->message =~ /Can't connect|Connect failed:/) {
			print "ERROR: We don't seem to be able to connect to the server: " . $response->message . "\n";
			exit 1;
		}
	}
	
	# Die if there's no HTTP Date: field
	unless ($server_date) {
		print "ERROR: No \"Date:\" field found in HTTP Headers\n";
		print $response->as_string;
		exit 1;
	}
	
	# Output server, client times and diff
	my $server_date_dm = ParseDate(scalar($server_date));
	print "Time difference: " . DateCalc($client_date_dm, $server_date_dm) . " (Server: $server_date_dm, Client: $client_date_dm)\n";
}
