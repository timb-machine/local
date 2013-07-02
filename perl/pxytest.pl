#!/usr/bin/perl
#
# $Id: pxytest.pl,v 1.2 2013-07-02 23:09:12 timb Exp $
#
# pxytest - test remote system for unsecured mail proxies
# POD documentation embedded at end.  View with:  perldoc pxytest
# home page:  <http://www.unicom.com/sw/pxytest/>
#
# Chip Rosenthal
# Unicom Systems Development
# <chip@unicom.com>
#

'$Revision: 1.2 $' =~ m!Revision: (\d+(\.\d+)+) !
	or die "$0: cannot determine version number";
my $VERSION = $1;

use strict;
eval 'use warnings';	# this pragma not avail in ver < 5.6.0

use Sys::Hostname;
use Time::gmtime;
use IO::Socket;
use Net::hostent;
use Getopt::Std;


#####
#
# ***** User Configurable Definitions *****
#

#
# $DEFAULT_MAIL_SERVER specifies the mail server you want to use.
# This test will attempt to connect to this server through the proxy.
# Override with -M.
#
# Normally, this should be set to "undef" and we will try to calculate
# an appropriate mail server.  If that doesn't work, then you'll need to
# set this to a specific mail server name or address.
#
my $DEFAULT_MAIL_SERVER = undef;

#
# Defines string that identifies the mail server SMTP welcome banner.
# Override with -S.
#
# This banner looks something like:
#
#     220 mail.soaustin.net ESMTP Postfix [NO UCE C=US L=TX]
#
# The "220" code is required by the spec, so that's a sure thing to search
# for.  However, if we hit a honeypot proxy that redirects SMTP elsewhere,
# we may get fooled into a false positive.  Therefore, it's better to
# use a banner that matches the first couple of words of what your server
# actually sends.
#
my $DEFAULT_SMTP_BANNER = "220 "; # trailing space is intentional

#
# Set default verbosity level.  Override with -v.
#
#     0 - Display nothing but program errors.
#     1 - Display final test result.
#     2 - Display individual test results.  
#     3 - Display details of individual tests.
#     4 - Display thread management information.
#
my $DEFAULT_VERBOSITY = 3;

#
# Number of threads to run.  Zero means run unthreaded.  Override with -t.
#
my $DEFAULT_THREADS = 0;

#
# $DEFAULT_SCAN is a "port_spec" that is used when none are given on
# the command line.
#
my $DEFAULT_SCAN = "basic";

#
# %TAGS_SCANLISTS associates mnemonic tags (like "basic") with a list of
# port_specs.  You may wish to tailor this to your preferences.  Feedback
# on these lists welcomed to <chip@unicom.com>.
#
my %TAGS_SCANLISTS = (

	#
	# By default, a scan covers the "basic" test of tests.  These are
	# the tests that cover the most frequently observed unsecured
	# proxies.
	#
	"basic" => [

		#
		# 80 - Web server with unsecured/misconfigured proxy function.
		#
		"80",
		"80/http-post",

		#
		# 3128 - Well known port for the "squid" web cache.
		#
		"3128",

		#
		# 8080 - Well known port for the "webcache" service.
		#
		# I'm not sure this "http-post" test is worthwhile.
		# If I don't see this catching anything, I'll likely
		# remove it at some point.
		#
		"8080",
		"8080/http-post",


		#
		# 8081 - Well known port for the "tproxy" transparent
		# proxy service.
		#
		"8081",

		#
		# 1080 - Well known port for the "socks" proxy service.
		#
		"1080/socks4",
		"1080/socks5",

		#
		# 23 - Well known port for the "telnet" service.  Also,
		# Wingate runs a proxy on this port.
		#
		# These tests can be troublesome.  If there is something
		# listening on the port, we could hang until the timeout
		# interval.  If we are running threaded it might be
		# better to have these done early.
		#
		"23/telnet",
		"23/cisco",
		"23/wingate",

		#
		# 6588 - The AnalogX product sets up an HTTP-CONNECT
		# proxy here.  This is typically caught with 1080/socks4,
		# but some networks are filtering 1080.
		#
		"6588",

		#
		# 1180 - David Ritz helped me identify a type of proxy
		# (brand or vendor unknown, I'm wondering if maybe it's
		# a trojan) that isn't caught by any of the above tests,
		# but is open to all of the following: 1180/socks4
		# 1180/socks5 1181/wingate 1182/http-connect.  This
		# device seems to have low sensitivity to probing.
		#
		"1180/socks4",

	],

	#
	# The "full" scan expands on the "basic" scan by adding tests
	# that have been observed to occasionally host open proxies.
	# If any of these probes find proxies with some moderate
	# frequency, then they probably ought to be elevated to the
	# "basic" scan list.
	#
	"full" => [
	
		#
		# Start with all the basic scans.
		#
		"basic",

		#
		# Add in the ports where I've seen reports of occasional
		# http-connect proxies.
		qw(81 85 1182 1282 4480 7033 8000 8085 8090 8095 8100 8105 8110 8888),

		#
		# See the discussion of "1180/socks4" in the "basic" scan.
		#
		qw(1180/socks5 1181/cisco 1181/telnet 1181/wingate),
	
	],

	"socks" => [qw(1080/socks4 1080/socks5)],
);

#
# $MAIL_MESSAGE_TEMPLATE is the template to generate a mail message
# we can send through an open proxy.  See the generate_mail_message()
# routine for information on the %VARIABLES% that can be used.
#
my $MAIL_MESSAGE_TEMPLATE =
q[To: %TO_ADDR%
From: %FROM_ADDR%
Date: %HDR_DATE%
Message-Id: %HDR_MSSGID%
Sender: %ORIG_SENDER%
Subject: open proxy test
X-Mailer: pxytest v%VERSION%
X-Proxy-Spec: %PROXY_ADDR%:%PROXY_PORT%/%PROXY_PROTOCOL% %MAIL_TAG%

This message is a test probe, passed through what appears to
be an open proxy.

This proxy test was initiated by <%ORIG_SENDER%>.
Please contact that user if you have any questions about this test.

Proxy parameters:

    Address:  %PROXY_ADDR%
    Port:     %PROXY_PORT%
    Type:     %PROXY_PROTOCOL%

This test was performed with the "pxytest" program.  For further
information see <http://www.unicom.com/sw/pxytest/>.
];

#
# Threshold on amount of input to read at one time, to prevent us
# from sucking down massive amounts of data.
#
my $INPUT_THRESHOLD = 2048;

#
# Timeouts on waiting to connect and waiting for input..
#
my $TIMEOUT_CONNECT = 30;
my $TIMEOUT_DATA = 60;


#
# ***** No user-serviceable parts below! *****
#
#####

#
# %TEST_BY_PROXY_TYPE associates proxy protocols with a test procedure.
#
my %TEST_BY_PROXY_TYPE = (
	"http-connect"	=> \&proxy_test_http_connect,
	"http-post"	=> "SPECIAL:http-post", # ugly
	"socks4"	=> \&proxy_test_socks4,
	"socks5"	=> \&proxy_test_socks5,
	"wingate"	=> \&proxy_test_wingate,
	"telnet"	=> \&proxy_test_telnet,
	"cisco"		=> \&proxy_test_cisco,
);

#
# Sequence to transmit a mail message via SMTP.
#
my @MAIL_SENDING_SEQUENCE = (
	{ 'send' => "HELO %HOSTNAME%\r\n",		'resp' => 250 },
	{ 'send' => "MAIL FROM:<%EMAILADDR%>\r\n",	'resp' => 250 },
	{ 'send' => "RCPT TO:<%EMAILADDR%>\r\n",	'resp' => 250 },
	{ 'send' => "DATA\r\n",				'resp' => 354 },
	{ 'send' => "%MESSAGE%",			'resp' => undef },
	{ 'send' => ".\r\n",				'resp' => 250 },
	{ 'send' => "QUIT\r\n",				'resp' => 221 },
);


my $USAGE = "usage: $0 [options ...] target_host [port_spec ...]  (try -h for help)\n";


sub help
{
	print $USAGE, qq{
Available Options:
    -a                  perform all tests (default = stop when open proxy found)
    -h                  display this help message
    -M mail_server      try to connect back to mail server instead of default
    -m mail_addr        transmit probe email (default = no probe)
    -S smtp_banner      identifies mail server banner (default = "$DEFAULT_SMTP_BANNER")
    -T mail_tag         insert tag in probe email (default = no tag)
    -t num_threads      run tests in multiple threads (default = $DEFAULT_THREADS)
    -v verbosity        change verbosity level (default = $DEFAULT_VERBOSITY)

Port Specification Format:
    min_port_number-[max_port_number][/proto]  (ex: 8080-8085/http-connect)
    proto values = }, join(", ", sort("all", "http", keys(%TEST_BY_PROXY_TYPE))), q{

Port Specification Aggregates:
};

	foreach my $key (sort keys %TAGS_SCANLISTS) {
		print "    $key = ", join(", ", @{$TAGS_SCANLISTS{$key}}), "\n";
	}

	print "\n";

	exit(0);

}

#
# Crack command line options.
#
my %opts;
getopts('ahM:m:S:T:t:v:', \%opts)
	or die $USAGE;
help() if ($opts{'h'});
my $All_flag = $opts{'a'};
# $opts{'M'} used when we calculate $MAIL_SERVER
my $Mail_addr = $opts{'m'};
my $Smtp_banner = $opts{'S'} || $DEFAULT_SMTP_BANNER;
my $Mail_tag = $opts{'T'};
my $Max_threads = (defined($opts{'t'}) ? $opts{'t'} : $DEFAULT_THREADS);
my $Verbosity = (defined($opts{'v'}) ? $opts{'v'} : $DEFAULT_VERBOSITY);
die $USAGE
	if (@ARGV == 0);

#
# Setup information for threading.
#
my $USE_THREADS = ($Max_threads > 1);
my $Num_threads = 0;
my $Curr_thread_id = undef;

#
# Counter, used when the $All_flag is set.
#
my $Num_open_proxies = 0;

#
# Calculate who we are and where we are.
#
my $Username = $ENV{'LOGNAME'}
	|| $ENV{'USER'}
	|| `whoami 2>/dev/null`
	|| `id --user --name 2>/dev/null`
	or die "$0: cannot determine your username\n";
my $Hostname = hostname();	# will croak if cannot determine hostname

#
# Locate the mail server we will connect back to.
#
my $MAIL_SERVER = locate_mailserver($opts{'M'} || $DEFAULT_MAIL_SERVER);
my $MAIL_PORT = 25;

#
# This ugliness is necessary on system that have restartable system calls.
# Not on a POSIX system?  Ha ha ... you lose.
#
# Actually, on such a system the usual $SIG{} mechanism may work.
# If you run into such a thing, let me know.
#
use POSIX ':signal_h';
my $Alarm_timeout = 0;
sub alarm_handler { $Alarm_timeout = 1; }
sigaction SIGALRM, new POSIX::SigAction "alarm_handler"
	or die "error setting SIGALRM handler: $!\n";


#
# Routines for output at given verbosity levels.
#

sub Print0
{
	my $leader = "";
	if ($USE_THREADS && $Verbosity > 1) {
		if ($Curr_thread_id) {
			$leader = sprintf("%-8s", "[$Curr_thread_id]");
		} else {
			$leader = "[MAIN]  ";
		}
	}
	print $leader, @_;
}

sub Print1 { Print0 @_ if ($Verbosity >= 1); }
sub Print2 { Print0 @_ if ($Verbosity >= 2); }
sub Print3 { Print0 @_ if ($Verbosity >= 3); }
sub Print4 { Print0 @_ if ($Verbosity >= 4); }
# only goes up to verbosity 4 right now ...


#####
#
# usage:	main($target_addr, [$port_spec, ...])
# function:	Main program procedure.
# returns:	Nothing.
#
# Does an exit(2) as soon as an open proxy is detected (unless $All_flag
# is set).  A successful return indicates no open proxies were found.
#
# This routine was pretty simple until I added the ugly pseudo-thread crap.
#
sub main
{
	my $target_addr = shift;
	my @portslist = (@_ > 0 ? @_ : $DEFAULT_SCAN);
	my(%testcond, $portspec, $th_id, $th_rc);

	$target_addr =~ /^\d+\.\d+\.\d+\.\d+$/ || gethostbyname($target_addr)
		or die "$0: unknown host \"$target_addr\"\n";

	#
	# We need to do result handling in a couple of places,
	# so create a subroutine for it.
	#
	my $_handle_result = sub {
		my ($th_id, $th_rc) = @_;
		return unless $th_rc;
		if (!$All_flag) {
			Print1 "Test complete - identified open proxy $testcond{$th_id}\n";
			thread_killall();
			exit(2);
		}
		Print1 "Identified open proxy $testcond{$th_id}\n";
		++$Num_open_proxies;
	};

	#
	# Treat the args as a queue ... keep pulling from the end until done.
	#
	while (@portslist > 0) {

		#
		# Pull the first entry out of the list.
		#
		$portspec = shift(@portslist);

		#
		# If this entry is a tag, expand it out and push
		# the values onto the front of the list.
		#
		if (defined($TAGS_SCANLISTS{$portspec})) {
			unshift(@portslist, @{$TAGS_SCANLISTS{$portspec}});
			next;
		}

		#
		# Parse the port specification in form:  num[-num][/proto]
		#
		my($minport, $maxport, $proto) = parse_portspec($portspec);
		if ($proto eq "all") {
			unshift(@portslist, map("$minport-$maxport/$_",
				keys %TEST_BY_PROXY_TYPE));
			next;
		}
		my $test_function = $TEST_BY_PROXY_TYPE{$proto}
			or die "$0: unknown proxy type \"$proto\"\n";

		#
		# Go through the range of ports specified.
		#
		foreach my $port ($minport .. $maxport) {

			#
			# Reap any threads that have finished.
			#
			while (($th_id = thread_reap(\$th_rc)) >= 0) {
				&$_handle_result($th_id, $th_rc);
			}

			#
			# Launch a thread and run the test.
			#
			if (($th_id = thread_launch()) == 0) {
				thread_exit(perform_proxy_test($target_addr, $port, $proto, $test_function));
			}

			#
			# Save off the test conditions for this thread-id.
			#
			$testcond{$th_id} = "${target_addr}:${port}/${proto}";

		}

	}

	#
	# Reap whatever threads have completed.
	#
	while (($th_id = thread_reap(\$th_rc)) >= 0) {
		&$_handle_result($th_id, $th_rc);
	}

	#
	# Now shutdown the thread limit to force blocking waits.
	#
	$Max_threads = 0;
	while ($Num_threads > 0) {
		Print3 sprintf("Waiting for %d thread%s to complete ...\n",
			$Num_threads, ($Num_threads > 1 ? "s" : ""));
		$th_id = thread_reap(\$th_rc);
		die "$0: unexpected return from thread_reap()"
			unless ($th_id > 0);
		&$_handle_result($th_id, $th_rc);
	}

	#
	# Tests are complete.
	#
	if ($All_flag && $Num_open_proxies > 0) {
		Print1 "Test complete - $Num_open_proxies proxies found\n";
		exit(2);
	}
	Print1 "Test complete - no proxies found\n";
}


#####
#
# usage:	locate_mailserver($mail_server)
# function:	Locate mail server for this host.
# returns:	Mail server address, in a text string, as a dotted quad.
#
# If a server (name or address) is handed to this procedure, then use that.
# Otherwise, we will try to locate an MX for the local host.
#

sub locate_mailserver
{
	my $mail_server = shift;

	if (!defined($mail_server)) {
		eval 'use Net::DNS';
		die "$0: you must define a mail server (Net::DNS unavailable)\n"
			if ($@);
		my @mx;
		my $hostname = $Hostname;
		while (! (@mx = mx($hostname))) {
			# Trim back to domain, hoping we can find an MX there.
			$hostname =~ s/^[^\.]+\.//
				or die "$0: cannot locate mail server for \"$hostname\"\n";
		}
		$mail_server = $mx[0]->exchange;
	}

	my $mail_server_addr;
	if ($mail_server =~ /^\d+\.\d+\.\d+\.\d+$/) {
		$mail_server_addr = $mail_server;
		Print3 "Using mail server: $mail_server_addr\n";
	} else {
		my $h = gethostbyname($mail_server)
			or die "$0: host lookup for \"$mail_server\" failed\n";
		$mail_server_addr = inet_ntoa($h->addr);
		Print3 "Using mail server: $mail_server_addr ($mail_server)\n";
	}

	return $mail_server_addr;
}


#####
#
# usage:	parse_portspec($port_spec)
# function:	Parse port specification in the form:  num[-num][/proto]
# returns:	($min, $max, $proto)
#
sub parse_portspec
{
	$_ = shift;
	m!^(\d+)(-(\d+))?(/([-\w]+))?$!
		or die "$0: bad port specification \"$_\"\n";
	my($min, $max, $proto) = ($1, $3 || $1, $5 || "http-connect");
	$proto = "http-connect"
		if ($proto eq "http");
	return($min, $max, $proto);
}


#####
#
# usage:	perform_proxy_test($addr, $port, $proto, $test_function)
# function:	Perform the specified proxy test.
# returns:	TRUE if an open proxy is encountered.
#
sub perform_proxy_test
{
	my($proxy_addr, $proxy_port, $proxy_proto, $test_function) = @_;

	#
	# Connect to the remote host on the specified port.
	#
	my $eol = ($USE_THREADS ? "\n" : " ... ");
	Print2 qq[Testing addr "$proxy_addr" port "$proxy_port" proto "$proxy_proto"$eol];
	my $sock = IO::Socket::INET->new(
		Proto => "tcp",
		PeerAddr => $proxy_addr,
		PeerPort => $proxy_port,
		Timeout => $TIMEOUT_CONNECT);

	if (!$sock) {
		Print2 ($USE_THREADS
			? "Cannot connect to $proxy_addr:$proxy_port\n"
			: "cannot connect\n");
		return 0;
	}
	Print2 ($USE_THREADS
		? "Connected to $proxy_addr:$proxy_port\n"
		: "connected\n");
	$sock->autoflush(1);

	#
	# Ass ugly special case.
	# See comments in test_http_post() for more info.
	#
	if ($test_function eq "SPECIAL:http-post") {
		my $mssg = generate_mail_message($proxy_addr, $proxy_port, $proxy_proto);
		my $is_open = proxy_test_http_post($sock, $mssg);
		$sock->close();
		if ($is_open) {
			Print2 "*** ALERT - open proxy detected\n";
			Print3 "Mail message has been sent to <$Mail_addr>\n"
				if ($Mail_addr);
		}
		return $is_open;
	}

	#
	# Execute the proxy test.
	#
	if (!&$test_function($sock)) {
		$sock->close();
		return 0;
	}
	Print2 "*** ALERT - open proxy detected\n";

	#
	# If an email address was given, transmit a probe message.
	#
	if ($Mail_addr) {
		my $mssg = generate_mail_message($proxy_addr, $proxy_port, $proxy_proto);
		if (transmit_mail_message($sock, $mssg)) {
			Print3 "Mail message has been sent to <$Mail_addr>\n";
		} else {
			Print3 "Warning - failed to transmit email message to <$Mail_addr>\n";
		}
	}

	$sock->close();
	return 1;
}


#####
#
# usage:	proxy_test_http_connect($sock)
# function:	Test for an open proxy using the "HTTP CONNECT" method.
# returns:	Return TRUE if open proxy detected.
#
sub proxy_test_http_connect
{
	my $sock = shift;

	wrsock($sock, "CONNECT ${MAIL_SERVER}:${MAIL_PORT} HTTP/1.0\r\n\r\n");
	$_ = rdsock($sock)
		or return 0;

	# should see something like: HTTP/1.0 200 Connection established
	m!^HTTP/\S+\s+(200)\s+!
		or return 0;

	# Wierd ... I'm finding some servers give a 200 to the CONNECT
	# request, but then serve up a document rather than making a
	# proxy connection.  They'll fail here.
	return found_smtp_banner($sock)
}



#####
#
# usage:	proxy_test_http_post($sock, $mssg)
# function:	Test for an open proxy using the "HTTP POST" method.
# returns:	Return TRUE if open proxy detected.
#
# This test is different from all the others.  It requires very ugly
# special case handling.  The problem is the entire HTTP-POST test
# (including transmitting a probe email) must be run blindly, and then
# results checked only after all the data are transmitted.
#
sub proxy_test_http_post
{
	my($sock, $mssg) = @_;

	#
	# Oddities I've seen ...
	#
	# Some proxies return HTTP status, some don't.  Thus, we don't
	# look for an HTTP success code, but set an abort on an HTTP
	# fail code.
	#
	# Some proxies transmit the HTTP headers as well as the payload.
	# thus we begin with a RSET to try to flush that garbage.
	#

	my $doc = "RSET\r\n";
	my $dispmssg;
	if ($Mail_addr) {
		foreach my $seq (@MAIL_SENDING_SEQUENCE) {
			if ($seq->{'send'} eq "%MESSAGE%") {
				$doc .= $mssg;
			} else {
				$doc .= $seq->{'send'};
			}
			$dispmssg = "(smtp dialog with probe email)";
		}
	} else {
		$dispmssg = $doc = "QUIT\r\n";
	}

	#
	# Blindly transmit the entire session.
	#
	wrsock($sock, "POST http://${MAIL_SERVER}:${MAIL_PORT}/ HTTP/1.0\r\n");
	wrsock($sock, "Content-Type: text/plain\r\n");
	wrsock($sock, "Content-Length: " . length($doc) . "\r\n\r\n");
	wrsock($sock, $doc . "\r\n", -mssg => $dispmssg);

	#
	# Now see if we get a connection to the mail server.
	#
	return found_smtp_banner($sock, -abort => ['^HTTP/1.\d [45]\d\d']);
}


#####
#
# usage:	proxy_test_socks4($sock)
# function:	Test for an unsecured SOCKS4 proxy.
# returns:	Return TRUE if open proxy detected.
#
# reference: http://www.socks.nec.com/protocol/socks4.protocol
#

my %SOCKS4_CONNECT_RESPONSES = (
	90 => "request granted",
	91 => "request rejected or failed",
	92 => "request rejected, ident required",
	93 => "request rejected, ident mismatch",
);

sub proxy_test_socks4
{

	my $sock = shift;
	my($mssg, $repcode, $repmssg);

	#
	# CONNECT request:
	#   VN		1 byte		socks version (4)
	#   CD		1 byte		command code (1 = connect)
	#   DSTPORT	2 bytes		destination port
	#   DSTIP	4 bytes		destination address
	#   USERID	variable	(not used here)
	#   NULL	1 byte
	#
	$mssg = pack("CCnA4x", 4, 1, $MAIL_PORT, inet_aton($MAIL_SERVER));
	wrsock($sock, $mssg);

	#
	# CONNECT reply:
	#   VN		1 byte		version of the reply code (should be 0)
	#   CD		1 byte		command code (the result)
	#   DSTPORT	2 bytes
	#   DSTIP	4 bytes
	#
	$mssg = rdsock($sock, -nbytes => 8)
		or return 0;
	$repcode = (unpack("C*", $mssg))[1];
	$repmssg = $SOCKS4_CONNECT_RESPONSES{$repcode}
		|| "unknown reply code";
	Print3 "socks reply code = $repcode ($repmssg)\n";
	return 0 unless ($repcode == 90);

	# grab the SMTP banner, but return TRUE even if that chokes
	found_smtp_banner($sock);
	return 1;
}


#####
#
# usage:	proxy_test_socks5($sock)
# function:	Test for an unsecured SOCKS5 proxy.
# returns:	Return TRUE if open proxy detected.
#
# reference: http://www.socks.nec.com/rfc/rfc1928.txt
#
# WARNING!!!  This is not tested.  I haven't found access to an open SOCKS5
# server yet.  If you can test this, please let me know.
#

my %SOCKS5_METHODS = (
	0 => "no authentication required",
	1 => "GSSAPI",
	2 => "username/password",
	255 => "no acceptable methods",
);

my %SOCKS5_CONNECT_RESPONSES = (
	0 => "succeeded",
	1 => "general SOCKS server failure",
	2 => "connection not allowed by ruleset",
	3 => "Network unreachable",
	4 => "Host unreachable",
	5 => "Connection refused",
	6 => "TTL expired",
	7 => "Command not supported",
	8 => "Address type not supported",
);

sub proxy_test_socks5
{
	my $sock = shift;
	my($mssg, $repcode, $repmssg);

	#
	# METHOD SELECT message:
	#  VER		1 byte	socks version (5)
	#  NMETHODS	1 byte	number of method identifies
	#  METHODS	var	list of methods (0 = no auth)
	#
	$mssg = pack("CCC", 5, 1, 0);
	wrsock($sock, $mssg);

	#
	# METHOD SELECT reply:
	#  VER		1 byte	socks version (5)
	#  METHOD	1 byte	method to use
	#
	$mssg = rdsock($sock, -nbytes => 2)
		or return 0;
	$repcode = (unpack("C*", $mssg))[1];
	$repmssg = $SOCKS5_METHODS{$repcode}
		|| "unknown or reserved method type";
	Print3 "socks reply code = $repcode ($repmssg)\n";
	return 0 unless ($repcode == 0);

	#
	# CONNECT request:
	#   VER		1 byte		socks version (5)
	#   CMD		1 byte		command code (1 = connect)
	#   RSV		1 byte		reserved
	#   ATYP	1 byte		address type (1 = IPv4)
	#   DST.ADDR	variable	destination address
	#   DST.PORT	2 bytes		destination port
	#
	$mssg = pack("CCCCa4n", 5, 1, 0, 1, inet_aton($MAIL_SERVER), $MAIL_PORT);
	wrsock($sock, $mssg);

	#
	# CONNECT reply:
	#   VER		1 byte		socks version (5)
	#   REP		1 byte		reply code
	#   RSV		1 byte		reserved
	#   ATYP	1 byte		address type (1 = IPv4)
	#   BND.ADDR	variable	server bound address
	#   BND.PORT	2 bytes		server bound port
	#
	$mssg = rdsock($sock, -nbytes => 10)
		or return 0;
	$repcode = (unpack("C*", $mssg))[1];
	$repmssg = $SOCKS5_CONNECT_RESPONSES{$repcode}
		|| "unknown or reserved reply code";
	Print3 "socks reply code = $repcode ($repmssg)\n";
	return 0 unless ($repcode == 0);

	# grab the SMTP banner, but return TRUE even if that chokes
	found_smtp_banner($sock);
	return 1;
}


#####
#
# usage:	proxy_test_wingate($sock)
# function:	Test for an open Wingate proxy.
# returns:	Return TRUE if open proxy detected.
#
sub proxy_test_wingate
{
	my $sock = shift;

	wrsock($sock, "${MAIL_SERVER}:${MAIL_PORT}\r\n");
	$_ = rdsock($sock)
		or return 0;
	return found_smtp_banner($sock, -abort => ["^Password:"]);
}



#####
#
# usage:	proxy_test_telnet($sock)
# function:	Test for an open telnet proxy.
# returns:	Return TRUE if open proxy detected.
#
# This is something that accepts a command:  telnet <dstaddr> <dstport>
#
# Here is an example of what one of these looks like (with the
# destination address elided to protect the guilty):
#
#	$ telnet a.b.c.d
#	Trying a.b.c.d...
#	Connected to a.b.c.d.
#	Escape character is '^]'.
#	ÿûÿûsrvfwcm telnet proxy (Version 5.5) ready:
#	tn-gw-> telnet 207.200.4.66 25
#	telnet 207.200.4.66 25
#	Trying 207.200.4.66 port 25...
#	ÿüÿüÿüConnected to 207.200.4.66.
#	220 mail.soaustin.net ESMTP Postfix [NO UCE C=US L=TX]
#
sub proxy_test_telnet
{
	my $sock = shift;

	wrsock($sock, "telnet $MAIL_SERVER $MAIL_PORT\r\n")
		or return 0;
	return found_smtp_banner($sock, -abort => ["^Password:"]);
}



#####
#
# usage:	proxy_test_cisco($sock)
# function:	Test for an proxy thru an unsecured Cisco router.
# returns:	Return TRUE if open proxy detected.
#
# The idea is you use the factory default login to access the router, and
# then you can use it like a telnet proxy.
#
# Here is a sample session:
#
#
#	[chip@mint chip]$ telnet a.b.c.d
#	Trying a.b.c.d...
#	Connected to a.b.c.d.
#	Escape character is '^]'.
#	
#	
#	User Access Verification
#	
#	Password: (bad password)
#	Password: (another bad password)
#	Password: (yet another bad password)
#	% Bad passwords
#	Connection closed by foreign host.
#
sub proxy_test_cisco
{
	my $sock = shift;

	rdsock_for_message($sock, -match => "^User Access Verification")
		or return 0;

	#
	# There should be a "Password:" prompt here, but we won't see
	# it until the newline is terminated.
	#
	wrsock($sock, "cisco\r\n");
	rdsock_for_message($sock, -match => "^Password:")
		or return 0;

	#
	# If the password worked, it's just a standard telnet proxy test.
	#
	return proxy_test_telnet($sock);
}


#####
#
# usage:	found_smtp_banner($sock, [options ...])
#		options passed to rdsock_for_message()
# function:	Look for the SMTP greeting banner from a mail server.
# returns:	TRUE if we can obtain an SMTP greeting banner.
#
# Actually, can be used to look for anything given the -match option.
#
sub found_smtp_banner
{
	my($sock, @args) = @_;
	# example:  220 mail.soaustin.net ESMTP Postfix [NO UCE C=US L=TX]
	return rdsock_for_message($sock, -match => "^\Q${Smtp_banner}", @args);
}


#####
#
# usage:	generate_mail_message($proxy_addr, $proxy_port, $proxy_proto)
# function:	Generate an email message to use as a test probe.
# returns:	Email message, with complete headers and body.
#
sub generate_mail_message
{
	my($proxy_addr, $proxy_port, $proxy_proto) = @_;
	use vars qw(%ENV);

	my $arpa_date = arpa_date();
	my $mssgid = sprintf("<pxytest-%d-%d\@%s>", time(), $$, $Hostname);

	#
	# Fixup SMTP sending sequence.
	#
	foreach my $seq (@MAIL_SENDING_SEQUENCE) {
		$seq->{'send'} =~ s/%HOSTNAME%/$Hostname/;
		$seq->{'send'} =~ s/%EMAILADDR%/$Mail_addr/;
	}

	$_ = $MAIL_MESSAGE_TEMPLATE;

	s/%VERSION%/$VERSION/g;

	s/%PROXY_ADDR%/$proxy_addr/g;
	s/%PROXY_PORT%/$proxy_port/g;
	s/%PROXY_PROTOCOL%/$proxy_proto/g;

	if (defined($Mail_tag)) {
		s/%MAIL_TAG%/$Mail_tag/g;
	} else {
		s/\s*%MAIL_TAG%//g;
	}

	s/%TO_ADDR%/$Mail_addr/g;
	s/%FROM_ADDR%/$Mail_addr/g;
	s/%HDR_DATE%/$arpa_date/g;
	s/%HDR_MSSGID%/$mssgid/g;

	s/%ORIG_SENDER%/$Username\@$Hostname/g;
	s/%ORIG_HOST%/$Hostname/g;

	s/\n/\r\n/g;
	return $_;
}


#####
#
# usage:	transmit_mail_message($sock, $mssg)
# function:	Transmit an email message via SMTP.
# returns:	TRUE if the message is successfully transmitted.
#
sub transmit_mail_message
{
	my($sock, $mssg) = @_;

	foreach my $seq (@MAIL_SENDING_SEQUENCE) {
		if ($seq->{'send'} eq "%MESSAGE%") {
			wrsock($sock, $mssg, -mssg => "(email message)");
		} else {
			my $resp = smtp_command($sock, $seq->{'send'});
			if ($seq->{'resp'} && $seq->{'resp'} != $resp) {
				return 0;
			}
		}
	}

	return 1;
}


#####
#
# usage:	smtp_command($sock, $command)
# function:	Transmit an SMTP command.
# returns:	The numeric SMTP response code, or 0 on error.
#
sub smtp_command
{
	my($sock, $command) = @_;
	my $rc = 0;
	my $cont = '-';

	wrsock($sock, $command);
	while (1) {
		$_ = rdsock($sock)
			or return 0;
		my($rc, $cont) = /^(\d\d\d)([- ])/
			or return 0;
		return $rc
			if ($cont eq " ");
	}
}


#####
#
# usage:	arpa_date([$secs_since_epoch])
# function:	Format a date for use in an RFC-2822 email message header.
# returns:	Date, as a string.
#
sub arpa_date
{
	my $gm = gmtime(shift || time());
	my @Day_name = ("Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat");
	my @Month_name = (
		"Jan", "Feb", "Mar", "Apr", "May", "Jun",
		"Jul", "Aug", "Sep", "Oct", "Nov", "Dec");

	sprintf("%-3s, %02d %-3s %4d %02d:%02d:%02d GMT",
		$Day_name[$gm->wday],
		$gm->mday, $Month_name[$gm->mon], 1900+$gm->year,
		$gm->hour, $gm->min, $gm->sec);

}


#####
#
# usage:	wrsock($sock, $data, [options ...])
#		options:
#		    -mssg => "message to display"
#		    -timeout => secs
# function:	Transmit data across socket, with timeout.
# returns:	TRUE if successful.
#
# Displays $data before sending it.
# A diagnostic message is printed if the write fails.
#
sub wrsock
{
	my $sock = shift;
	my $data = shift;
	my %args = @_;
	my $mssg = $args{-mssg} || $data;
	my $timeout = $args{-timeout} || $TIMEOUT_DATA;

	Print3 ">>> ", printable_mssg($mssg), "\n";

	alarm($timeout);
	my $rc = $sock->print($data);
	alarm(0);

	Print3 ">>> ERROR: error writing socket: $!\n"
		if (!$rc);
	return $rc;
}


#####
#
# usage:	rdsock_for_message($sock, [options ...])
#		options:
#		  -match => pattern
#		  -abort => [pattern, ...]
#		  -limit = nbytes
# function:	Look for the indicated match pattern.
# returns:	TRUE if we can obtain the pattern.
#
sub rdsock_for_message
{
	my($sock, %args) = @_;
	my $matchpat = $args{-match}
		or die "$0: must specify \"-match\" for rdsock_for_message()\n";
	my $abortlist = $args{-abort};
	my $limit = $args{-limit} || $INPUT_THRESHOLD;
	my $amount_read = 0;

	while (1) {
		$_ = rdsock($sock)
			or return 0;
		/$matchpat/
			and return 1;
		if ($abortlist) {
			foreach my $pat (@$abortlist) {
				/$pat/
					and return 0;
			}
		}
		$amount_read += length($_);
		if ($limit && $amount_read > $limit) {
			Print3 "<<< WARNING: input threshold exceeded - bailing out\n";
			return 0;
		}
	}
	return 0;
}


#####
#
# usage:	rdsock($sock, [options ...])
#		options:
#		  -timeout => secs
#		  -bytes => n (default is to read a line)
# function:	Retrieve data from socket, with timeout.
# returns:	Value retrieved.
#
# Displays data retrieved.
# Returns undefined on timeout, end of input, or read failure.
#
sub rdsock
{
	my $sock = shift;
	my %args = @_;
	my $timeout = $args{-timeout} || $TIMEOUT_DATA;
	my $nb = $args{-nbytes};

	my $data;
	$Alarm_timeout = 0;
	alarm($timeout);
	if (defined($nb)) {
		$sock->read($data, $nb);
	} else {
		$data = $sock->getline();
	}
	alarm(0);

	if ($Alarm_timeout) {
		Print3 "<<< TIMEOUT: timeout waiting for response\n";
		undef $data;
	} elsif (!defined($data)) {
		Print3 "<<< EOF: end of input\n";
	} else {
		Print3 "<<< ", printable_mssg($data), "\n";
	}
	return $data;
}


#####
#
# usage:	printable_mssg($data)
# function:	Generate a printable string from an arbitrary data string.
# returns:	Printable string.
#
# If the data is printable text data, then it is returned with trailing
# newlines elided.
#
# If the data includes unprintable content, then it is displayed as a
# list of byte values.
#
sub printable_mssg
{
	$_ = shift;

	if (/^[[:print:][:space:]]*$/) {
		s/\r/\\r/g;
		s/\n/\\n/g;
		return $_
	}
	my @x = unpack("C*", $_);
	return "binary message: " . join(" ", map(sprintf("%d", $_), @x));
}


#####
#
# Thread crap.
#
# Synopsis:
#     $thread_id = thread_launch();
#     thread_exit($exit_status);
#     $thread_id = thread_reap(\$thread_status);
#     thread_killall();
#
# The threading system allows processes to be created, and an 8-bit status
# value returned to the main program.  Each thread is actually a separate
# process, with the thread status passed back as the process exit status.
#
# thread_launch() - Start a new thread.  Returns the thread-id to the calling
# process, and 0 to the newly created thread.
#
# thread_exit() - A thread terminates, and passes the $exit_status back to
# the calling thread.
#
# thread_reap() - The $exit_status from a recently terminated thread is
# retrieved.  Normally if now thread has terminated, returns zero as the
# $thread_id.  If, however, the maximum number of threads are running,
# it blocks until a thread terminates.
#
# thread_killall() - All threads are terminated.
#
# If $USE_THREADS is false, the behavior of these routines changes so that
# no threads are created, and the most recent $exit_status value is saved
# for retrieval.
#

my $Thread_counter = 0;		# Used to assign unique thread-ids.
my %Thread_table;		# Associate process-ids with thread-ids.
my @Thread_save_status;		# Hold status for when $USE_THREADS is false.


sub thread_launch
{
	return 0
		if (!$USE_THREADS);
	die "$0: attempt to exceed thread limit ($Max_threads)"
		if ($Num_threads >= $Max_threads);

	++$Thread_counter;
	my $pid = fork();
	die "$0: fork failed: $!"
		unless defined($pid);

	#
	# Child becomes the spawned thread.
	#
	if ($pid == 0) {
		$Curr_thread_id = $Thread_counter;
		return 0;
	}

	#
	# Parent returns id of newly created thread.
	#
	# We pause a bit before returning, to give the child a chance to run.
	# This helps prevent blasting the target proxy with an arsenal of
	# processes.  Normally the entire process will complete with just
	# a thread or two.  We'll spawn multiple threads only if the tests
	# start bogging down.
	#
	# Note this will make the test run longer in the best case.  I'm
	# finding in practice it adds a couple of seconds to the test
	# time, but I'm on a modem.  The penalty would be even higher on
	# high speed connections.
	#
	# The bottom line is when you run with threads enabled, you take
	# a small-to-medium penalty on the typical-to-best cases, in
	# return for a huge benefit in the worst cases.  This means -t
	# really is a lose in a lot of cases.
	#
	++$Num_threads;
	Print4 "thread: launched id=$Thread_counter pid=$pid ($Num_threads/$Max_threads)\n";
	sleep(1);
	return $Thread_table{$pid} = $Thread_counter;
}


sub thread_exit
{
	my $st = shift;
	if (!$USE_THREADS) {
		# not running threads - save off status
		push(@Thread_save_status, $st);
		return;
	}
	Print4 "thread: terminating id=$Curr_thread_id status=$st\n";
	exit($st)
}


use POSIX ":sys_wait_h";

sub thread_reap
{
	my($th_result_ref) = @_;

	if (!$USE_THREADS) {
		# not running threads - retrieve saved status
		return -1
			unless (@Thread_save_status > 0);
		$$th_result_ref = pop(@Thread_save_status);
		return 0;
	}

	return -1
		unless ($Num_threads > 0);
	my $pid = waitpid(-1, ($Num_threads >= $Max_threads ? 0 : &WNOHANG));
	die "$0: waitpid failed: $!\n"
		if ($pid < 0);
	if ($pid == 0) {
		# WNOHANG given, no processes waiting
		return -1;
	}
	die sprintf("$0: pid $pid exited with status 0x%04X", $?)
		if ($? < 0 || $? & 0xFF);

	my $st = ($? >> 8);
	$$th_result_ref = $st
		if ($th_result_ref);

	--$Num_threads;
	my $thread_id = delete $Thread_table{$pid};
	Print4 "thread: reaped id=$thread_id status=$st\n";
	return $thread_id;
}


sub thread_killall
{
	kill 'SIGTERM', keys %Thread_table;
}



##############################################################################
#
# Start of execution.
#

$| = 1; # autoflush stdout
main(@ARGV);
exit(0);

#
##############################################################################

__END__


=head1 NAME

pxytest - test proxy server for unsecured mail relay

=head1 SYNOPSIS

B<pxytest>
[ B<-a> ]
[ B<-h> ]
[ B<-M> I<mail_server> ]
[ B<-m> I<mail_addr> ]
[ B<-S> I<smtp_banner> ]
[ B<-T> I<mail_tag> ]
[ B<-t> I<num_threads> ]
[ B<-v> I<verbosity> ]
I<target_host>
[ I<port_spec> ... ]


=head1 DESCRIPTION

The B<pxytest> utility performs a test on I<target_host> (given as a
host name or address) to locate an unsecured proxy that allows allow
connections to a mail server.  Spammers use such hosts to distribute
vast amounts of junk email.

Normally, B<pxytest> will not actually attempt to relay mail through
the proxy, only verify that an open proxy exists and can connect to a
mail server.  If the test runs to completion without encountering an
unsecured proxy, the program terminates with a message:

Z<>	Test complete - no proxies found

Normally, as soon as the program encounters an open proxy, it terminates
with a message:

Z<>	Test complete - identified open proxy I<addr>:I<port>/I<protocol>

The following options are available.

=over 4

=item B<-a>

Find all open proxies.  Instead of terminating as soon as an open proxy
is detected, B<pxytest> will continue on to perform the full set of
tests.  At completion, it will indicate the number of open proxies
detected.

=item B<-h>

Display a help message and then exit.  The help message provides
information on defaults and definitions that may have been modified by
your local administrator.

=item B<-M> I<mail_server>

Specifies a target I<mail_server>, given as a name or number.  B<pxytest>
will attempt to connect to this server through the proxy.  See B<Mail
Server Selection> for more information.

=item B<-m> I<mail_addr>

A probe email message is transmitted to I<mail_addr>.  Normally,
B<pxytest> stops as soon as it verifies connection to the SMTP server.
When this option is given it continues on to send an email to the
indicated recipient.

=item B<-S> I<smtp_banner>

Specifies string that identifies the SMTP banner from the mail server.
See the B<Mail Server Selection> section for more information.

=item B<-T> I<mail_tag>

An arbitrary I<mail_tag> is added to the probe email headers.  This tag
may be used, for example, to serialize the email so it may be correlated
with a particular incident.  This option has no effect unless B<-m> was
specified.

=item B<-t> I<num_threads>

B<This option is experimental.>
The test is accelerated by running up to I<num_threads> probes in
parallel.  Under best-to-normal case conditions, this will actually
B<slow down> the test, taking it longer to complete.  In the worst
case situation, however, where certain tests are pausing for long
times waiting for server responses, this can greatly reduce the
total test time.

=item B<-v> I<verbosity>

Controls the amount of output messages produced.  The verbosity levels
are:

    0 - Display nothing but program errors.
    1 - Display final test result.
    2 - Display individual test results.  
    3 - Display details of individual tests.
    4 - Display thread management information.

The default verbosity level is 3.

=back


=head2 The I<port_spec> Arguments

Exhaustive testing for open proxies is impractical.  Proxies may appear
on any of 65,536 TCP ports.  Also, there are a number of different forms
of proxies, each requiring its own test.  At 50msec/test, it could take
over 6 hours to test a single host.

The user must direct the B<pxytest> test sequence.  This is done with
I<port_spec> arguments.  These may be simply a tag name (discussed
shortly) or a specification in the form:

Z<>	I<min>[-I<max>][/I<proto>]

where I<min> is the starting port number of the scan, I<max> is the ending
port number of the scan, and I<proto> is the proxy mechanism to test.
If I<max> is not specified (it usually isn't), then a single-port scan
is done.  The possible I<proto> values are: B<http-connect>, B<http-post>,
B<http>, B<socks4>, B<socks5>, B<telnet>, B<cisco>, B<wingate>, and
B<all>.  If I<proto> is not specified then it defaults to B<http-connect>.
(The next section describes what these proxy mechanisms mean.)

The I<port_spec> may also be a mnemonic tags.  As distributed, there
are three tags defined:

=over 4

=item B<basic>

A basic set of tests that covers most common cases.  If no I<port_spec>
argument is given on the command line, the default is to do a B<basic>
scan.

=item B<full>

All of the basic tests plus several more that have been reported in
less common instances.

=item B<socks>

A shortcut for:  1080/socks4 1080/socks5

=back

Your local administrator may have modified this script to change the
definition of these tags or added additional tags.  Run B<pxytest>
with the B<-h> option to get a list of all the tags and their exact
definitions.


=head2 Proxy Mechanisms

There are a number of different proxy mechanisms that can be abused
for mail relay.  The mechanisms supported by this utility include:

=over 4

=item B<http-connect>

A web proxy or cache that supports the C<HTTP CONNECT>
mechanism. See I<CERT Vulnerability Note VU#150227>
(http://www.kb.cert.org/vuls/id/150227) for further information.

This is the most common type of unsecured proxy.  It may appear on any
TCP port.  Some of the common locations are port 3128 (the well known
port for I<squid>), port 8080 (the well known port for I<webcache>), and
port 8081 (the well known port for I<tproxy>).  Unsecured or misconfigured
web servers can often act as proxies, so these are often found on port 80
(the well known port for I<http>).  The I<AnalogX Proxy> uses port 6588.

If no I<proto> is specified in a I<port_spec>, it defaults to
B<http-connect>.

=item B<http>

An alias for B<http-connect>.

=item B<http-post>

A web proxy or cache that supports access to a URL via
the C<HTTP POST> mechanism.  This vulnerability is not well
documented, but according to the OPM stats it's the second
most prevalent type.

=item B<socks4>

SOCKS version 4 proxy.  See the I<SOCKS Version 4 Overview>
<http://www.socks.nec.com/socksv4.html> for further information on
this service.  TCP port 1080 is the well known port allocated to I<socks>.

=item B<socks5>

SOCKS version 5 proxy.  See the I<SOCKS Version 5 Overview>
<http://www.socks.nec.com/socksv5.html> for further information on
this service.  TCP port 1080 is the well known port allocated to I<socks>.

=item B<telnet>

A proxy that accepts a command in the form:

Z<>	B<telnet> I<dstaddr> I<dstport>

and establishes a connection to the indicated destination.

=item B<cisco>

An unsecured Cisco router that allows login with the factory default
values.  Once a user is logged into the router, they can use it as a
telnet proxy.

=item B<wingate>

The B<WinGate> Internet Sharing/Proxy Server by Deerfield.com.  See their
corporate web site <http://www.deerfield.com/products/wingate/> for
further information on this product.  Such a proxy accepts a specification
in the form:

Z<>	I<dstaddr>:I<dstport>

and establishes a connection to the indicated destination.  This proxy
typically appears on TCP port 23, which, confusingly enough, is the well
known port reserved for the I<telnet> service.

=item B<all>

This value is expanded out to all the available test mechanisms.

=back


=head2 Mail Server Selection

The B<pxytest> utility attempts connection to a target mail server,
and declares a proxy as open if it succeeds.  The target mail server is
selected by the following process:

=over 4

=item o

If the B<-M> command line option is given, the I<mail_server> value it
specifies (host name or address) is used.

=item o

Otherwise, if the B<$DEFAULT_MAIL_SERVER> parameter is defined in
the script, that is selected.  Typically that parameter is left
undefined, although the local administrator may choose to modify
the script to set a value.

=item o

Otherwise, if the I<perl> Net::DNS module is installed, the utility will
attempt to determine the mail server (MX) for the local host and use that.

=back

If none of these methods may be used, the utility terminates with an
error.

The utility will attempt to recognize the mail server by its SMTP
welcome banner, which typically looks something like:

    220 mail.soaustin.net ESMTP Postfix [NO UCE C=US L=TX]

By default, it declares success when it sees a line beginning with "220 "
(two-two-oh-space).  In certain conditions, this may be a problem.

Some rare mail servers do not use the 220 code.  If, for example,
the mail server does not want to accept incoming mail, it may use some
other code.  Such a server can be used by B<pxytest>, although the B<-m>
option won't work.

Some proxies are actually honeypots that are used to trap spammers and
crackers.  These honeypots may redirect SMTP connections.  So B<pxytest>
will declare success when it sees the SMTP welcome banner generated by
the honeypot.

In these cases, the B<-S> option may be used to specify a more specific
match for the SMTP banner.  The I<smtp_banner> argument will specify
a fixed string that appears at the start of the banner.  For example,

    -S "220 mail.soaustin.net"

might be a good way to ensure B<pxytest> has connected back to the
server that gives the SMTP banner shown above.


=head2 Probe Email

When the B<-m> option is specified, the utility attempts to send a probe
email message through the target mail server.  Here is the header from
a sample probe message:

	To: chip+pxytest@unicom.com
	From: chip+pxytest@unicom.com
	Subject: open proxy test
	X-Mailer: pxytest v1.17
	X-Proxy-Spec: 192.108.105.34:1080/socks4 ID-000034

The C<To> and C<From> headers were specified with the B<-m> option.
The C<X-Mailer> header may be used to simplify recognition and
sorting of incoming test probes.  The C<X-Proxy-Spec> header
identifies the proxy, plus any tag that may have been given
with the B<-T> option.


=head1 EXIT STATUS

An exit status of 0 means the test ran to completion without finding
any open proxies.  An exit status of 2 means that an open proxy was
detected.  Any other non-zero exit status indicates some sort of error.


=head1 DIAGNOSTICS

This section provides additional explanation for selected error messages:

=over 4

=item unknown host I<target_host>

=item unknown proxy type I<proto>

=item bad port specification I<num>

These all indicate a problem with the I<port_spec> given on the command
line.

=item error setting SIGALRM handler

This utility uses the POSIX interface to set timeout alarms.  This error
likely indicates you are running on a non-POSIX system.  If you run into
this, please contact the author.

=item cannot locate mailserver for "I<hostname>"

Was unable to locate a mail exchanger (MX) for your host or your domain.
This would happen if there is no MX for your host or your domain.
It also could happen if there are DNS problems.  This can be worked
around by either using the B<-M> option or modifying the script to define
a B<$DEFAULT_MAIL_SERVER> value.

=item you must define a mail server (Net::DNS unavailable)

The automatic mail server lookup cannot run, because your system does
not have the I<perl> Net::DNS module installed.  If you do not want to
install this module, then you will need to specify the target mail server.
Either use the B<-M> option or modify the script to define define a
B<$DEFAULT_MAIL_SERVER> value.

=item host lookup for I<hostname> failed

The indicated host was identified as the target mail server to use, but
B<pxytest> was unable to determine the IP address of that host.  This
typically results from DNS problems.  Either resolve the DNS problems,
or specify the target mail host as an address rather than a name.

=item Cannot get host name of local machine

This diagnostic is produced by the I<perl> Sys::Hostname module.  See
the documentation on that module for information.

=item cannot determine your username

A number of methods were attempted to determine your username, none of
which worked.  Please contact the author if you get this message.


=back


=head1 BUGS

Proxies may appear on any TCP port.  A complete test would require an
exhaustive scan of all available ports, which is infeasible.  Instead, the
B<basic> and B<full> scans cover ports that (based on past observation)
are mostly likely to be bound to a proxy service.  The author welcomes
feedback on the ports definitions for the B<basic> and B<full> scans.
The author also welcomes information on additional proxy mechanisms that
may be used for email abuse (spam).

Ideally, the B<-S> option should not be required.  We ought be able to
probe the target mail server to get the SMTP banner.  We don't do this
automatically, because in some cases (e.g. running the test from a host
on a network that blocks outbound port 25) it won't work.

The threading is an ugly hack to address the inordinately long test
times against a proxy that is not responding.  Hell, it isn't even
real threading.  It's a lame facsimile implemented with I<fork()>.

The port 23 tests can be troublesome.  If there is something listening
at that port, these tests frequently will hang until timeout occurs.
I ought to investigate whether there is some way they all can be
combined into some smarter, optimized test.

Severely overloaded proxies are prone to false negatives.  That is,
B<pxytest> might fail to connect because the proxy is throttled or
dropping connections or otherwise busy puking its guts out.  So it
will declare this proxy as closed, even though a repeated attempt
might prove otherwise.


=head1 SEE ALSO

services(5),
httpd(8),
sockd(8)


=head1 ACKNOWLEDGMENTS

I found the following programs helpful in developing this utility.

=over 4

=item I<Blitzed Open Proxy Monitor>

<http://www.blitzed.org/bopm/>

=item I<Proxy Stress Tester>

<ftp://ftp.monkeys.com/pub/proxy/pxstress-1.1.tar.gz>

=back


=head1 AUTHOR

 Chip Rosenthal
 Unicom Systems Development
 <chip@unicom.com>

 $Id: pxytest.pl,v 1.2 2013-07-02 23:09:12 timb Exp $
 See <http://www.unicom.com/sw/pxytest/> for latest version.

