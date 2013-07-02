#!/usr/bin/perl

#
# Copyright (c) 2005,2006 by Matteo Cantoni (nothink.org)
#
# snmpcheck is a tool to get information via SNMP protocols on Windows, Linux,
# Cisco, HP-UX, SunOS, AIX and other platforms that supports a SNMP agent.
# snmpcheck has been tested on GNU/Linux, *BSD and Windows (Cygwin and ActivePerl) systems.
# snmpcheck is distributed under GPL license and based on "Athena-2k" script by jshaw. 
#
# Note: "TCP connections enumeration" can be very long, beyond 60 seconds. Use -d flag to disable it.  
#

use strict;
use Getopt::Std;
use IO::Socket;
use Net::IP;
use Net::SNMP;
use Number::Bytes::Human qw(format_bytes);
use Time::HiRes qw( usleep ualarm gettimeofday tv_interval );

my $name        = "snmpcheck.pl";
my $version     = "v1.6";
my $description = "snmp enumerator";
my $copyright   = "Copyright (c) 2005,2006";
my $author      = "Matteo Cantoni (nothink.org)";

#####################################################################################################
# MIBs Involved 
my $mibDescr                       = "1.3.6.1.2.1.1.1.0";            # System Description
my $mibNTDomain                    = "1.3.6.1.4.1.77.1.4.1.0";       # NT Primary Domain
my $mibUptime                      = "1.3.6.1.2.1.1.3.0";            # System Uptime
my $mibContact                     = "1.3.6.1.2.1.1.4.0";            # System Contact
my $mibName                        = "1.3.6.1.2.1.1.5.0";            # System Name
my $mibLocation                    = "1.3.6.1.2.1.1.6.0";            # System Location
my $mibServices                    = "1.3.6.1.4.1.77.1.2.3.1.1";     # Services (add to it)
my $mibAccounts                    = "1.3.6.1.4.1.77.1.2.25";        # User Accounts
my $mibMemSize                     = "1.3.6.1.2.1.25.2.2.0";         # Total System Memory
my $mibMotd                        = "1.3.6.1.4.1.42.3.1.3.0";       # Motd (Solaris)
# Devices
my $mibDevice                      = "1.3.6.1.2.1.25.3.2.1.3";       # Devices list
my $mibDevStatus                   = "1.3.6.1.2.1.25.3.2.1.5";       # Devices status
# Processs
my $mibProcesses                   = "1.3.6.1.2.1.25.1.6.0";         # System Processes 
my $mibRunIndex                    = "1.3.6.1.2.1.25.4.2.1.1";       # Running PIDs 
my $mibRunName                     = "1.3.6.1.2.1.25.4.2.1.2";       # Running Programs
my $mibRunPath                     = "1.3.6.1.2.1.25.4.2.1.4";       # Processes Path
my $mibRunParameters               = "1.3.6.1.2.1.25.4.2.1.5";       # Processes Parameters
my $mibRunType                     = "1.3.6.1.2.1.25.4.2.1.6";       # Processes Type
my $mibRunStatus                   = "1.3.6.1.2.1.25.4.2.1.7";       # Processes Status
my $mibProName                     = "1.3.6.1.4.1.42.3.12.1.1.10";   # Running Process Name (Solaris)
my $mibProPid                      = "1.3.6.1.4.1.42.3.12.1.1.1";    # Running Process Pid (Solaris)
my $mibProUser                     = "1.3.6.1.4.1.42.3.12.1.1.8";    # Running Process User (Solaris)
# Storage
my $mibSDType                      = "1.3.6.1.2.1.25.2.3.1.2";       # Storage Device Type
my $mibStorDescr                   = "1.3.6.1.2.1.25.2.3.1.3";       # Storage Description
my $mibStoreUnits                  = "1.3.6.1.2.1.25.2.3.1.4";       # Storage Units 
my $mibStorSize                    = "1.3.6.1.2.1.25.2.3.1.5";       # Storage Total Size
my $mibStorUsed                    = "1.3.6.1.2.1.25.2.3.1.6";       # Storage Used
my $mibStoreHP                     = "1.3.6.1.4.1.11.2.3.1.2";       # Storage Description (HP-UX)
my $mibPtype                       = "1.3.6.1.2.1.25.3.8.1.4";       # Partition Type
# Network
my $mibInt                         = "1.3.6.1.2.1.2.2.1.2";          # Network Interfaces
my $mibIntMTU                      = "1.3.6.1.2.1.2.2.1.4";          # Net Int MTU Size
my $mibIntSpeed                    = "1.3.6.1.2.1.2.2.1.5";          # Net Int Speed
my $mibIntBytesIn                  = "1.3.6.1.2.1.2.2.1.10";         # Net Int Octets In
my $mibIntBytesOut                 = "1.3.6.1.2.1.2.2.1.16";         # Net Int Octects Out
my $mibIntPhys                     = "1.3.6.1.2.1.2.2.1.6";          # Int MAC addr
my $mibAdminStat                   = "1.3.6.1.2.1.2.2.1.7";          # Int up/down?
my $mibIPForward                   = "1.3.6.1.2.1.4.1.0";            # IP Forwarding?
my $mibIPAddr                      = "1.3.6.1.2.1.4.20.1.1";         # Int IP Address
my $mibNetmask                     = "1.3.6.1.2.1.4.20.1.3";         # Int IP Netmask
# Software
my $mibInstalled                   = "1.3.6.1.2.1.25.6.3.1.2";       # Installed Programs
# IIS
my $http_totalBytesSentLowWord     = "1.3.6.1.4.1.311.1.7.3.1.2.0";  # totalBytesSentLowWord
my $http_totalBytesReceivedLowWord = "1.3.6.1.4.1.311.1.7.3.1.4.0";  # totalBytesReceivedLowWord
my $http_totalFilesSent            = "1.3.6.1.4.1.311.1.7.3.1.5.0";  # totalFilesSent
my $http_currentAnonymousUsers     = "1.3.6.1.4.1.311.1.7.3.1.6.0";  # currentAnonymousUsers
my $http_currentNonAnonymousUsers  = "1.3.6.1.4.1.311.1.7.3.1.7.0";  # currentNonAnonymousUsers
my $http_totalAnonymousUsers       = "1.3.6.1.4.1.311.1.7.3.1.8.0";  # totalAnonymousUsers
my $http_totalNonAnonymousUsers    = "1.3.6.1.4.1.311.1.7.3.1.9.0";  # totalNonAnonymousUsers
my $http_maxAnonymousUsers         = "1.3.6.1.4.1.311.1.7.3.1.10.0"; # maxAnonymousUsers
my $http_maxNonAnonymousUsers      = "1.3.6.1.4.1.311.1.7.3.1.11.0"; # maxNonAnonymousUsers
my $http_currentConnections        = "1.3.6.1.4.1.311.1.7.3.1.12.0"; # currentConnections
my $http_maxConnections            = "1.3.6.1.4.1.311.1.7.3.1.13.0"; # maxConnections
my $http_connectionAttempts        = "1.3.6.1.4.1.311.1.7.3.1.14.0"; # connectionAttempts
my $http_logonAttempts	           = "1.3.6.1.4.1.311.1.7.3.1.15.0"; # logonAttempts
my $http_totalGets	           = "1.3.6.1.4.1.311.1.7.3.1.16.0"; # totalGets
my $http_totalPosts	           = "1.3.6.1.4.1.311.1.7.3.1.17.0"; # totalPosts
my $http_totalHeads	           = "1.3.6.1.4.1.311.1.7.3.1.18.0"; # totalHeads
my $http_totalOthers	           = "1.3.6.1.4.1.311.1.7.3.1.19.0"; # totalOthers
my $http_totalCGIRequests          = "1.3.6.1.4.1.311.1.7.3.1.20.0"; # totalCGIRequests
my $http_totalBGIRequests          = "1.3.6.1.4.1.311.1.7.3.1.21.0"; # totalBGIRequests
my $http_totalNotFoundErrors       = "1.3.6.1.4.1.311.1.7.3.1.22.0"; # totalNotFoundErrors
# Shares
my $mibShareName                   = "1.3.6.1.4.1.77.1.2.27.1.1";    # Reports Share Names
my $mibSharePath                   = "1.3.6.1.4.1.77.1.2.27.1.2";    # Reports Share Path
my $mibShareComm                   = "1.3.6.1.4.1.77.1.2.27.1.3";    # Reports Share Comments
# ARP Info
my $mibipnet2mediaif		   = "1.3.6.1.2.1.4.22.1.1";         # ARP
my $mibipnet2physical		   = "1.3.6.1.2.1.4.22.1.2";         # ARP
my $mibipnet2medianet		   = "1.3.6.1.2.1.4.22.1.3";         # ARP
my $mibipnet2mediat		   = "1.3.6.1.2.1.4.22.1.4";         # ARP
# Routing Info
my $mibRouteDest                   = "1.3.6.1.2.1.4.21.1.1";         # Route Destinations
my $mibRouteMetric                 = "1.3.6.1.2.1.4.21.1.3";         # Route Metric
my $mibRouteNHop                   = "1.3.6.1.2.1.4.21.1.7";         # Route Next Hop 
my $mibRouteMask                   = "1.3.6.1.2.1.4.21.1.11";        # Route Mask
# TCP Connections
my $mibTCPState                    = "1.3.6.1.2.1.6.13.1.1";         # TCP Connect State
my $mibTCPLAddr                    = "1.3.6.1.2.1.6.13.1.2";         # TCP Local Address
my $mibTCPLPort                    = "1.3.6.1.2.1.6.13.1.3";         # TCP Local Port
my $mibTCPRAddr                    = "1.3.6.1.2.1.6.13.1.4";         # TCP Remote Address
my $mibTCPRPort                    = "1.3.6.1.2.1.6.13.1.5";         # TCP Remote Port
# UDP Listening
my $mibUDPLAddr                    = "1.3.6.1.2.1.7.5.1.1";          # UDP Local Address
my $mibUDPLPort                    = "1.3.6.1.2.1.7.5.1.2";          # UDP Local Port
#####################################################################################################

my @hosts;
my $checksun  = 0;
my $webport   = 80;
my $localtime = localtime();
my ($status,$session,$error);

our ($opt_t,$opt_i,$opt_p,$opt_c,$opt_v,$opt_r,$opt_d,$opt_T,$opt_l,$opt_h);
getopts("t:i:p:c:v:r:dT:lh");

my $community = $opt_c || "public";
my $port      = $opt_p || 161;
my $snmpver   = $opt_v || 1;
my $retries   = $opt_r || 1;
my $timeout   = $opt_T || 45;

my $usage = "$name $version - $description\n$copyright by $author\n
 Usage ./$name -t <ip address> [-i] [-p] [-c] [-v] [-r] [-d] [-T] [-l] [-h]\n
\t-t : target host or ip address range;
\t-i : optional list of targets;
\t-p : snmp port; default port is $port;
\t-c : snmp community; default is $community;
\t-v : snmp version; default is $snmpver;
\t-r : request retries; default is $retries;
\t-d : disable \"TCP connections\" enumeration!
\t-T : timeout; default is $timeout. Max is 60;
\t-l : enable logging;
\t-h : show help menu;
\n Examples:\n
        ./$name -t 192.168.0.1
        ./$name -t 192.168.0.0/24
        ./$name -t 192.168.0.1-192.168.0.10
        ./$name -i iplist\n\n";

die $usage if  $opt_h;
die $usage if !$opt_t && !$opt_i;
die $usage if  $opt_t &&  $opt_i;
die " [-] Error: max timeout value is 60 seconds!\n" if $timeout > 60;

$|=1;

{ my $flip = "|"; sub wheel { print $flip = { reverse split //, '|/\|-\/-|', -1 }->{ $flip }, "\b"; } }

$SIG{INT} = sub {
	close LOG if $opt_l;
	exit(1);
};

print "$name $version - $description\n$copyright by $author\n\n";

{ my $flip = "|"; sub wheel { print $flip = { reverse split //, '|/\|-\/-|', -1 }->{ $flip }, "\b"; } }

if ($opt_t){
	print " Creating ip address list...";
	my $ip = new Net::IP ("$opt_t");
	do { &wheel; push @hosts,$ip->ip(); } while (++$ip);
	print "\n\n";
} 

if ($opt_i){
	open(IPLIST, "<$opt_i") || die " [-] Error: cannot open the ip address list file: $!\n";
		chomp (@hosts = <IPLIST>);
	close (IPLIST);
}

my $n = $#hosts + 1;
print " [*] $n host/s to scan\n [*] starting...\n\n";

foreach(@hosts){

	print " [*] try to connect to $_...\n";

	my $pid = fork();

	die "\n [-] Error: fork() failed: $!" unless defined $pid;

	if($pid>0){
		wait();
		next;
	}else{
		local $SIG{ALRM} = sub { exit(0); };
		alarm $timeout;
		Connect($_);
		alarm 0;
		exit(0);
	}
}

print "\n";

exit(0);

sub Connect {

	my $target = shift;
	for ($target) { s/^\s+//; s/\s+$//; }

	my $logfile = "snmpcheck-log-$target.txt";

	if ($opt_l){
		open (LOG, ">$logfile") || die " [-] Error: cannot open the log file $logfile: $!\n";
	}

	$SIG{ALRM} = sub {
		close LOG if $opt_l;	
		print " [-] $target, connection timeout! Use -T flag to increase timeout.\n\n";
		exit(0);
	};

	($session,$error) = Net::SNMP->session(
		Hostname  => $target,
		Community => $community,
		Domain    => 'udp',
		Port      => $port,
		Version   => $snmpver,
		Timeout   => $timeout,
		Retries   => $retries
	);

	if ($session){

		my $start_time = [gettimeofday];

		my $hostname  = getrequest($mibName);
		my $descr     = getrequest($mibDescr);
		my $uptime    = getrequest($mibUptime);
		my $ntdomain  = getrequest($mibNTDomain);
		my $contact   = getrequest($mibContact);
		my $location  = getrequest($mibLocation);
		my $motd      = getrequest($mibMotd);

		if ($descr){
			chomp $descr;
			for ($descr){s/^\s+//; s/\s+$//;}
		}

		chomp $motd if $motd;
	
		$checksun = 1 if $descr =~ /^Sun/;

		printer(" [x] $target, connecting... starting check at $localtime\n\n");

		printer(" Hostname        : $hostname\n") if $hostname;
		printer(" Description     : $descr\n")    if $descr;
		printer(" Uptime (snmpd)  : $uptime\n")   if $uptime;
		printer(" Domain          : $ntdomain\n") if $ntdomain;
		printer(" Contact         : $contact\n")  if $contact;
		printer(" Location        : $location\n") if $location;
		printer(" Motd            : $motd\n")     if $motd;
	
		if ($descr !~ /^Sun|^-|^Fibre|^Cisco/){
	
			my @stordescr = gettable($mibStorDescr);
			my @storsize  = gettable($mibStorSize); 
			my @storused  = gettable($mibStorUsed); 
			my @storunits = gettable($mibStoreUnits); 
			my @sdtype    = gettable($mibSDType);
			my @ptype     = gettable($mibPtype);

			if ($#stordescr > 0){
				printer("\n [*] Hardware and storage informations\n"); border();
		
				my $a = 0;
				foreach(@stordescr){
	
					my %storagetypes = (
						'1.3.6.1.2.1.25.2.1.1'  => 'Other',
						'1.3.6.1.2.1.25.2.1.2'  => 'Ram',
						'1.3.6.1.2.1.25.2.1.3'  => 'VirtualMemory',
						'1.3.6.1.2.1.25.2.1.4'  => 'FixedDisk',
						'1.3.6.1.2.1.25.2.1.5'  => 'RemovableDisk',
						'1.3.6.1.2.1.25.2.1.6'  => 'FloppyDisk',
						'1.3.6.1.2.1.25.2.1.7'  => 'CompactDisc',
						'1.3.6.1.2.1.25.2.1.8'  => 'RamDisk',
						'1.3.6.1.2.1.25.2.1.9'  => 'FlashMemory',
						'1.3.6.1.2.1.25.2.1.10' => 'NetworkDisk'
					);

					my %fstypes = (
						'1.3.6.1.2.1.25.3.9.1'  => 'Other',
						'1.3.6.1.2.1.25.3.9.2'  => 'Unknown',
						'1.3.6.1.2.1.25.3.9.3'  => 'BerkeleyFFS',
						'1.3.6.1.2.1.25.3.9.4'  => 'Sys5FS',
						'1.3.6.1.2.1.25.3.9.5'  => 'Fat',
						'1.3.6.1.2.1.25.3.9.6'  => 'HPFS',
						'1.3.6.1.2.1.25.3.9.7'  => 'HFS',
						'1.3.6.1.2.1.25.3.9.8'  => 'MFS',
						'1.3.6.1.2.1.25.3.9.9'  => 'NTFS',
						'1.3.6.1.2.1.25.3.9.10' => 'VNode',
						'1.3.6.1.2.1.25.3.9.11' => 'Journaled',
						'1.3.6.1.2.1.25.3.9.12' => 'iso9660',
						'1.3.6.1.2.1.25.3.9.13' => 'RockRidge',
						'1.3.6.1.2.1.25.3.9.14' => 'NFS',
						'1.3.6.1.2.1.25.3.9.15' => 'Netware',
						'1.3.6.1.2.1.25.3.9.16' => 'AFS',
						'1.3.6.1.2.1.25.3.9.17' => 'DFS',
						'1.3.6.1.2.1.25.3.9.18' => 'Appleshare',
						'1.3.6.1.2.1.25.3.9.19' => 'RFS',
						'1.3.6.1.2.1.25.3.9.20' => 'DGCFS',
						'1.3.6.1.2.1.25.3.9.21' => 'BFS'
					);
	
					printer(" $_\n");
					printer("\tDevice type     : $storagetypes{$sdtype[$a]}\n") if $storagetypes{$sdtype[$a]};

					if ($ptype[$a]){
						if ($fstypes{$ptype[$a]}){
							printer("\tFilesystem type : $fstypes{$ptype[$a]}\n");
						} else{
							printer("\tFilesystem type : unknown\n");
						}
					} else{
						printer("\tFilesystem type : unknown\n");
					}

					if ($storunits[$a]){
						printer("\tDevice units    : $storunits[$a]\n");

						if ($storsize[$a]){
							$storsize[$a] = ($storsize[$a] * $storunits[$a]);
							my $s = format_bytes($storsize[$a]);
							printer("\tMemory size     : $s\n");
						}
					
						if ($storused[$a]){
							$storused[$a] = $storused[$a] * $storunits[$a];
							my $s = format_bytes($storused[$a]);
							printer("\tMemory used     : $s\n");
						}
				
						if ($storsize[$a] && $storused[$a]){
							my $free = $storsize[$a] - $storused[$a];
							$free = format_bytes($free);
							printer("\tMemory free     : $free\n");
						}
					}
	
					printer("\n");
					$a++;
				}
			}
		}

		Mountpoints()    if $descr !~ /^-|^Hardware|^Fibre|^Cisco/;
		Devices()        if $descr !~ /^-|^Cisco|^Fibre|^Sun/; 
		Accounts()       if $descr !~ /^-|^Cisco|^Fibre|^Linux|^Sun/; 
		Processes()      if $descr !~ /^-|^Cisco|^Fibre|^Sun/;
		Netinfo();
		ARPinfo();
		Routinginfo();
		Netservices();
		Tcpconnections() if !$opt_d;
		Udpports();
		IIS($target)     if $descr =~ /^Hardware/;
		Software()       if $descr !~ /^-|^Cisco|^Fibre|^Sun/;
		Shares()         if $descr !~ /^-|^Cisco|^Fibre|^Linux/;

		$session->close;
		
		my $end_time = [gettimeofday];
		my $elapsed = tv_interval($start_time,$end_time);
		printer("\n [x] $target, log file $logfile created") if $opt_l;
		printer("\n [x] $target, finished! Scanned in $elapsed seconds\n");
		
		close LOG if $opt_l;
	}else{
		printer(" [-] Error: $target, timeout while connecting to server!");
	}
}	

sub Devices {

	my @deviceslist  = gettable($mibDevice);
	my @devicestatus = gettable($mibDevStatus);

	if ($#deviceslist > 0){
		printer("\n [*] Devices\n"); border();

		printf     " %5s   Name\n\n", "Status";
		printf LOG " %5s   Name\n\n", "Status" if $opt_l;

		my $a = 0;
		foreach(@deviceslist){
			
			$status = "unknown";
	
			if ($devicestatus[$a] eq '1'){
				$status = "unknown";
			}elsif($devicestatus[$a] eq '2'){
				$status = "running";
			}elsif($devicestatus[$a] eq '3'){
				$status = "warning";
			}elsif($devicestatus[$a] eq '4'){
				$status = "testing";
			}elsif($devicestatus[$a] eq '5'){
				$status = "down";
			}

			printf     " %7s  $_\n", $status if $_;
			printf LOG " %7s  $_\n", $status if $_ && $opt_l;
			$a++;
		}	
	}
}

sub Accounts {

	my @accounts = gettable($mibAccounts);

	if ($#accounts > 0){
		printer("\n\n [*] User accounts\n"); border();

		@accounts = sort @accounts;
		foreach(@accounts){
			printer(" $_\n");
		}
	}
}

sub Processes {

	if ($checksun == 1){
	
		# Solaris
		my @runproid    = gettable("1.3.6.1.4.1.42.3.12.1.1.1");  # psProcessID 
		my @runparid    = gettable("1.3.6.1.4.1.42.3.12.1.1.2");  # psParentProcessID
		my @runprosize  = gettable("1.3.6.1.4.1.42.3.12.1.1.3");  # psProcessSize
		my @runcputime  = gettable("1.3.6.1.4.1.42.3.12.1.1.4");  # psProcessCpuTime
		my @runstate    = gettable("1.3.6.1.4.1.42.3.12.1.1.5");  # psProcessState
		my @runtty      = gettable("1.3.6.1.4.1.42.3.12.1.1.7");  # psProcessTTY
		my @runusername = gettable("1.3.6.1.4.1.42.3.12.1.1.8");  # psProcessUserName
		my @runuserid   = gettable("1.3.6.1.4.1.42.3.12.1.1.9");  # psProcessUserID
		my @runname     = gettable("1.3.6.1.4.1.42.3.12.1.1.10"); # psProcessName
		my @runstatus   = gettable("1.3.6.1.4.1.42.3.12.1.1.11"); # psProcessStatus
	
		if ($#runproid > 0){
			printer("\n\n [*] Processes\n"); border();

			print "   Pid    Ppid    Size Cputime  State      TTY     Username   Uid          Name    Status\n\n";
			for (my $a = 0; $a < $#runproid; $a++){
				printf     " %6s %6s %6s %6s %6s %10s %10s %6s %15s %6s\n", 
$runproid[$a],$runparid[$a],$runprosize[$a],$runcputime[$a],$runstate[$a],$runtty[$a],$runusername[$a],$runuserid[$a],$runname[$a],$runstatus[$a];
				printf LOG " %6s %6s %6s %6s %6s %10s %10s %6s %15s %6s\n", 
$runproid[$a],$runparid[$a],$runprosize[$a],$runcputime[$a],$runstate[$a],$runtty[$a],$runusername[$a],$runuserid[$a],$runname[$a],$runstatus[$a] if $opt_l;
			}
		}
	} else{
		# Other
		my $processes = getrequest($mibProcesses);
		my @runindex  = gettable($mibRunIndex);
		my @runname   = gettable($mibRunName);
		my @runpath   = gettable($mibRunPath);
		my @runtype   = gettable($mibRunType);
		my @runstatus = gettable($mibRunStatus);
	
		if ($#runindex > 0){
			printer("\n\n [*] Processes\n"); border();

			printer(" Total processes : $processes\n\n") if $processes;
			printer(" Process type    : 1 unknown, 2 operating system, 3 device driver, 4 application\n"); 
			printer(" Process status  : 1 running, 2 runnable, 3 not runnable, 4 invalid\n\n"); 

			printf " %10s %25s %13s %15s  Process path\n\n", "Process id","Process name","Process type","Process status";
			printf LOG " %10s %25s %13s %15s  Process path\n\n", "Process id","Process name","Process type","Process status" if $opt_l;

			for (my $a = 0; $a < $#runindex; $a++){
				if ($runname[$a] ne " System Idle Process"){
					printf     " %10s %25s %13s %15s  $runpath[$a]\n", $runindex[$a],$runname[$a],$runtype[$a],$runstatus[$a];
					printf LOG " %10s %25s %13s %15s  $runpath[$a]\n", $runindex[$a],$runname[$a],$runtype[$a],$runstatus[$a] if $opt_l;
				}
			}
		}
	}
}

sub Netinfo {

	my @int         = gettable($mibInt);
	my @mtu         = gettable($mibIntMTU);
	my @intspeed    = gettable($mibIntSpeed);
	my @intbytesin  = gettable($mibIntBytesIn);
	my @intbytesout = gettable($mibIntBytesOut);
	my @intphys     = gettable($mibIntPhys);
	my @ipaddr      = gettable($mibIPAddr);
	my @netmask     = gettable($mibNetmask);
	my @adminstat   = gettable($mibAdminStat);
	my $ipforward   = getrequest($mibIPForward);

	if ($ipforward eq "0" || $ipforward eq "2") { $ipforward = "no"; }

	if ($#int > 0){ 
		printer("\n\n [*] Network interfaces\n"); border();
		printer(" IP Forwarding Enabled   : $ipforward\n\n");

		$#int++;
		for (my $a = 0; $a < $#int; $a++){

			chomp $int[$a];

			if ($adminstat[$a] eq "0"){
				$adminstat[$a] = "down";
			} else {
				$adminstat[$a] = "up";
			}

			if ($intspeed[$a] !~ /-/){
				$intspeed[$a] = $intspeed[$a] / 1000000;
				printer(" Interface               : [ $adminstat[$a] ] $int[$a]\n");
				printer("\tHardware Address : $intphys[$a]\n")       if $intphys[$a];
				printer("\tInterface Speed  : $intspeed[$a] Mbps\n") if $intspeed[$a];
				printer("\tIP Address       : $ipaddr[$a]\n")        if $ipaddr[$a];
				printer("\tNetmask          : $netmask[$a]\n")       if $ipaddr[$a];
				printer("\tMTU              : $mtu[$a]\n")           if $mtu[$a];

				if ($intbytesin[$a]){
					printer("\tBytes In         : $intbytesin[$a]");
					$intbytesin[$a] = format_bytes($intbytesin[$a]);
					printer(" ($intbytesin[$a])\n"); 
				}

				if ($intbytesout[$a]){
					printer("\tBytes Out        : $intbytesout[$a]");
					$intbytesout[$a] = format_bytes($intbytesout[$a]);
					printer(" ($intbytesout[$a])\n");
				}
	
				printer("\n");
			}
		}
	}
}

sub Netservices {

	my @services = gettable($mibServices);

	if ($#services > 0){
		printer("\n\n [*] Network services\n"); border();

		@services = sort @services;
		foreach(@services){
			printer(" $_\n");
		}
	}
}
	
sub ARPinfo{
    
     my @mifs  = gettable($mibipnet2mediaif);
     my @phys = gettable($mibipnet2physical);
     my @net  = gettable($mibipnet2medianet);
     my @type = gettable($mibipnet2mediat); 
     
        if ($#mifs > 0){
                printer("\n [*] ARP information\n"); border();
                printer("       Interface\tMAC Address\tIP\t\tType (3=Dynamic)\n\n");

                for (my $a = 0; $a < $#mifs; $a++){
                        printf     "%17s%17s%17s%9s\n", $mifs[$a], $phys[$a], $net[$a], $type[$a];
                        printf LOG "%17s%17s%17s%9s\n", $mifs[$a], $phys[$a], $net[$a], $type[$a] if $opt_l;
                }
        }


}


sub Routinginfo {
	my @routedest	= gettable($mibRouteDest);
	my @routenhop	= gettable($mibRouteNHop);
	my @routemask	= gettable($mibRouteMask);
	my @routemetric	= gettable($mibRouteMetric);

	if ($#routedest > 0){
		printer("\n [*] Routing information\n"); border();
		printer("      Destination\t  Next Hop\t       Mask\tMetric\n\n");

		for (my $a = 0; $a < $#routedest; $a++){
			printf     "%17s%17s%17s%9s\n", $routedest[$a], $routenhop[$a], $routemask[$a], $routemetric[$a];
			printf LOG "%17s%17s%17s%9s\n", $routedest[$a], $routenhop[$a], $routemask[$a], $routemetric[$a] if $opt_l;
		}
	}
}

sub Tcpconnections {

	my @tcpstate = gettable($mibTCPState);
	my @tcpladdr = gettable($mibTCPLAddr); 
	my @tcplport = gettable($mibTCPLPort);
	my @tcpraddr = gettable($mibTCPRAddr);
	my @tcprport = gettable($mibTCPRPort);

	if ($#tcpstate > 0){
		printer("\n\n [*] TCP connections\n"); border();
		printer("   Local Address   Port      Remote Address   Port       State\n\n");

		for (my $a = 0; $a < $#tcpstate; $a++){
			if ($tcpstate[$a] eq "1")  { $tcpstate[$a] = "(closed)";       }
			if ($tcpstate[$a] eq "2")  { $tcpstate[$a] = "(listening)";    }
			if ($tcpstate[$a] eq "3")  { $tcpstate[$a] = "(syn sent)";     }
			if ($tcpstate[$a] eq "4")  { $tcpstate[$a] = "(syn received)"; }
			if ($tcpstate[$a] eq "5")  { $tcpstate[$a] = "(established)";  }
			if ($tcpstate[$a] eq "6")  { $tcpstate[$a] = "(fin wait1)";    }
			if ($tcpstate[$a] eq "7")  { $tcpstate[$a] = "(fin wait2)";    }
			if ($tcpstate[$a] eq "8")  { $tcpstate[$a] = "(close wait)";   }
			if ($tcpstate[$a] eq "9")  { $tcpstate[$a] = "(last ack)";     }
			if ($tcpstate[$a] eq "10") { $tcpstate[$a] = "(closing)";      } 
			if ($tcpstate[$a] eq "11") { $tcpstate[$a] = "(time wait)";    }
			if ($tcpstate[$a] eq "12") { $tcpstate[$a] = "(delete tcb)";   }

			printf     " %15s %6s   %17s %6s %15s\n", $tcpladdr[$a], $tcplport[$a], $tcpraddr[$a], $tcprport[$a], $tcpstate[$a];
			printf LOG " %15s %6s   %17s %6s %15s\n", $tcpladdr[$a], $tcplport[$a], $tcpraddr[$a], $tcprport[$a], $tcpstate[$a] if $opt_l;
		}
	}
}

sub Udpports {

	my @udpladdr = gettable($mibUDPLAddr);
	my @udplport = gettable($mibUDPLPort);

	if ($#udpladdr > 0){
		printer("\n\n [*] Listening UDP ports\n"); border();
		printer("   Local Address   Port\n\n");

		for (my $a = 0; $a < $#udpladdr; $a++){
			printf     " %15s %6s\n", $udpladdr[$a], $udplport[$a];
			printf LOG " %15s %6s\n", $udpladdr[$a], $udplport[$a] if $opt_l;
		}
	}
}

sub Software {

	my @installed = gettable($mibInstalled);

	if ($#installed > 0){
		printer("\n\n [*] Software components\n"); border();
		my @soft;
		for (my $a = 0; $a < $#installed; $a++){
			push @soft, "$installed[$a]";
		}

		@soft = sort @soft;
		foreach(@soft){
			printer(" $_\n");
		}
	}
}

sub IIS {

	my $target = shift;
		
	my $http_totalBytesSentLowWord     = getrequest($http_totalBytesSentLowWord); 
	my $http_totalBytesReceivedLowWord = getrequest($http_totalBytesReceivedLowWord); 
	my $http_totalFilesSent            = getrequest($http_totalFilesSent);
	my $http_currentAnonymousUsers     = getrequest($http_currentAnonymousUsers);
	my $http_currentNonAnonymousUsers  = getrequest($http_currentNonAnonymousUsers);
	my $http_totalAnonymousUsers       = getrequest($http_totalAnonymousUsers);
	my $http_totalNonAnonymousUsers    = getrequest($http_totalNonAnonymousUsers);
	my $http_maxAnonymousUsers         = getrequest($http_maxAnonymousUsers);
	my $http_maxNonAnonymousUsers      = getrequest($http_maxNonAnonymousUsers);
	my $http_currentConnections        = getrequest($http_currentConnections);
	my $http_maxConnections            = getrequest($http_maxConnections);
	my $http_connectionAttempts        = getrequest($http_connectionAttempts);
	my $http_logonAttempts             = getrequest($http_logonAttempts);
	my $http_totalGets                 = getrequest($http_totalGets);
	my $http_totalPosts                = getrequest($http_totalPosts);
	my $http_totalHeads                = getrequest($http_totalHeads);
	my $http_totalOthers               = getrequest($http_totalOthers);
	my $http_totalCGIRequests          = getrequest($http_totalCGIRequests);
	my $http_totalBGIRequests          = getrequest($http_totalBGIRequests );
	my $http_totalNotFoundErrors       = getrequest($http_totalNotFoundErrors);

	if ($http_totalFilesSent){
		printer("\n\n [*] Web server informations\n"); border();
	}

	if ($http_totalBytesSentLowWord){
		if ($http_totalBytesSentLowWord =~ /\d+/){
			$http_totalBytesSentLowWord = format_bytes($http_totalBytesSentLowWord);
			printer(" totalBytesSentLowWord     : $http_totalBytesSentLowWord\n");
		} else {
			printer(" totalBytesSentLowWord     : -\n");
		}
	}
			
	if ($http_totalBytesReceivedLowWord){
		if ($http_totalBytesReceivedLowWord =~ /\d+/){
			$http_totalBytesReceivedLowWord = format_bytes($http_totalBytesReceivedLowWord);
			printer(" totalBytesReceivedLowWord : $http_totalBytesReceivedLowWord\n");
		} else {
			printer(" totalBytesReceivedLowWord : -\n");
		}
	}

	printer(" totalFilesSent            : $http_totalFilesSent\n")           if $http_totalFilesSent;
	printer(" currentAnonymousUsers     : $http_currentAnonymousUsers\n")    if $http_currentAnonymousUsers;
	printer(" currentNonAnonymousUsers  : $http_currentNonAnonymousUsers\n") if $http_currentNonAnonymousUsers;
	printer(" totalAnonymousUsers       : $http_totalAnonymousUsers\n")      if $http_totalAnonymousUsers;
	printer(" totalNonAnonymousUsers    : $http_totalNonAnonymousUsers\n")   if $http_totalNonAnonymousUsers;
	printer(" maxAnonymousUsers         : $http_maxAnonymousUsers\n")        if $http_maxAnonymousUsers;
	printer(" maxNonAnonymousUsers      : $http_maxNonAnonymousUsers\n")     if $http_maxNonAnonymousUsers;
	printer(" currentConnections        : $http_currentConnections\n")       if $http_currentConnections;
	printer(" maxConnections            : $http_maxConnections\n")           if $http_maxConnections;
	printer(" connectionAttempts        : $http_connectionAttempts\n")       if $http_connectionAttempts;
	printer(" logonAttempts             : $http_logonAttempts\n")            if $http_logonAttempts;
	printer(" totalGets                 : $http_totalGets\n")                if $http_totalGets;
	printer(" totalPosts                : $http_totalPosts\n")               if $http_totalPosts;
	printer(" totalHeads                : $http_totalHeads\n")               if $http_totalHeads;
	printer(" totalOthers               : $http_totalOthers\n")              if $http_totalOthers;
	printer(" totalCGIRequests          : $http_totalCGIRequests\n")         if $http_totalCGIRequests;
	printer(" totalBGIRequests          : $http_totalBGIRequests\n")         if $http_totalBGIRequests;
	printer(" totalNotFoundErrors       : $http_totalNotFoundErrors\n")      if $http_totalNotFoundErrors;
}

sub Mountpoints {
	
	my @StorDescr = gettable($mibStorDescr);

	if ($#StorDescr > 0){
		printer("\n [*] Mountpoints\n"); border();
		
		for (my $a = 0; $a < $#StorDescr; $a++){
			printer(" $StorDescr[$a]\n") if (grep(/\//,$StorDescr[$a]));
		}
	}
}

sub Shares {

	my @ShareName = gettable($mibShareName);
	my @SharePath = gettable($mibSharePath);
	my @ShareComm = gettable($mibShareComm);

	if ($#ShareName > 0){
		printer("\n\n [*] Non-administrative shares\n"); border();

		for (my $a = 0; $a < $#ShareName; $a++){
			printer(" Share Name : $ShareName[$a]\n");
			printer(" Path       : $SharePath[$a]\n");
			printer(" Comments   : $ShareComm[$a]\n\n");
		}
	}
}

sub getrequest {

	my $response = "";
	
	if (!($response = $session->get_request($_[0]))){
		return "-";
	} else {
		my $Return = $response->{$_[0]};
		return $Return;
	}
}

sub gettable {

	my @Return;
	my $response = "";

	if (!($response = $session->get_table($_[0]))){
		return "-";
	}

	my $x = 0;
	my $key;

	foreach $key (sort keys %$response){
		if ($$response{$key} ne " Virtual Memory"){
			$Return[$x] = $$response{$key};
			$x++;
		}
	}

	return @Return;
}

sub border {
	if ($opt_l){
		print     " "; print     "-" x 95; print     "\n\n";
		print LOG " "; print LOG "-" x 95; print LOG "\n\n";
	} else {
		print " "; print "-" x 95; print "\n\n";
	}
}

sub printer {
	my @string = @_;

	if ($opt_l){
		print @string;
		print LOG @string;
	} else {
		print @string;
	}
}

