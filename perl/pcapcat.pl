#!/usr/bin/perl
#################################################################################################
#              pcapcat 
#################################################################################################
# This script reads a PCAP file and prints out all the connections in the file and gives
# the user the option of dumping the content of the TCP stream
#
# Author: Kristinn Gudjonsson
# Version : 0.1b
# Date : 17/08/09
#
# Copyright 2009 Kristinn Gudjonsson (kristinn ( a t ) log2timeline (d o t) net)
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.


use strict;
use Getopt::Long; # read parameters
use Pod::Usage;
use Net::Pcap;
use NetPacket::Ethernet;
use NetPacket::IP;
use NetPacket::TCP;
use NetPacket::UDP;
use NetPacket::ICMP;


# version information
my $version = '0.1';
# define how many numbers of connections to show on each screen
my $buffer = 10;

# other variables (no not edit unless you know what you are doing)
my ($out,$file);
my $filter;
my $filter_c;
my $print_help;
my ($ether,$ip,$trans);
my $err;
my $packets;
my $index;
my $show_version;
my $dump_nr;
my $only_syn = 1;
my $all;
my $i = 0;
my $s_index = 1;

# read options
GetOptions(
        "filter:s"=>\$filter,
        "read:s"=>\$file,
	"write:s"=>\$out,
	"only-syn!"=>\$only_syn,
	"all!"=>\$all,
        "version!"=>\$show_version,
        "dump:s"=>\$dump_nr,
        "help|?!"=>\$print_help
) or pod2usage( 2 );

# check if we are asking for help
pod2usage(1) if $print_help;

# print versioning information
show_version() if $show_version;

# check if we are showing all packets
$only_syn = 0 if ( $all );

# check if file exists
pod2usage(2) unless -e $file;

# reset the index value
$index = 1;

# start reading the file
$packets = Net::Pcap::open_offline( $file, \$err );
if( defined $err )
{
	die 'Unable to read the PCAP file ' . $err . "\n";
}


# now we need to check if we are going to read all packets or dump a certain traffic
if( defined $dump_nr )
{
	# dump a certain traffic

	# first check if out file is defined
	die( 'Unable to determine output file, use the parameter -w FILE' ) unless defined $out;

	# try to open the out file (create a new one)
	if( -e $out )
	{
		print "Overwriting file: $out\n";
	}
	open( OF, '>' . $out );

	binmode( OF );

	# now to dump a certain stream
	dump_stream( $dump_nr );

	close( OF );

}
else
{
	# normal run, print all the packets

	# check if there is a filter defined
	$s_index = 0 if defined $filter;	# if we have a filter defined, then we cannot show the index value (in this version)
	$filter = 'tcp' unless defined $filter;


	if( ! $s_index )
	{
		print STDERR 'Using PCAP filter.  Please be aware that in this version of pcapcat, there isn\'t support for index and dumping data while using predefined filters', "\n";
		print STDERR 'Please use the tool without custom filters to get the index variable printed out, for use with -d to dump data',"\n";
	}
	# create the filter
	Net::Pcap::compile( $packets, \$filter_c, $filter, 1, undef );
	Net::Pcap::setfilter( $packets, $filter_c );

	# read all the packets
	Net::Pcap::loop( $packets, -1, \&read_all_packets, '' ); 
	
	# close the network file (since we have finished our processing)
	Net::Pcap::close( $packets );
}

#########################################################################################################
#		routines
#########################################################################################################

# 	dump_stream
# this function takes as a parameter an index into the pcap file and reads all packets that belong
# to that particular stream
sub dump_stream
{
	my $in = shift;
	my %header;
	my $packet;

	if( $only_syn )
	{
		$filter = 'tcp[13] & 0x3f = 0x02';
	}
	else
	{
		# the filter we are looking for is just defined as a TCP
		$filter = 'tcp';

	}
		
	Net::Pcap::compile( $packets, \$filter_c, $filter, 1, undef );
	Net::Pcap::setfilter( $packets, $filter_c );
		
	# find the correct packet
	for( my $i=0; $i < $in; $i++ )
	{
		$packet = Net::Pcap::next( $packets, \%header );
	}

	# strip header information and get the data part
	$ether = NetPacket::Ethernet->decode( $packet );	
	$ip = NetPacket::IP->decode( $ether->{'data'} );
	$trans = NetPacket::TCP->decode( $ip->{'data'} );

	# now I need to read all the data part of the entire conversation 
	# and dump it into a file
	# construct a filter
	$filter = 'tcp and (host ' . $ip->{'src_ip'} . ' and host ' . $ip->{'dest_ip'} . ') and ( port ' . $trans->{'dest_port'} . ' and port ' . $trans->{'src_port'} . ')';
	Net::Pcap::compile( $packets, \$filter_c, $filter,1,undef);
	Net::Pcap::setfilter( $packets, $filter_c );

	# read all the packets that belong to this particular stream
	Net::Pcap::loop( $packets, -1, \&dump_to_file, '' );
	
	return 1;
}

#	dump_to_file
#
# A small function which reads packets created in the dump_stream function
# and prints them to a file, an output file, to contain the information
# found inside streams
sub dump_to_file
{
	my $user_data = shift;
	my $header = shift;
	my $pack = shift;

	# strip headers	
	$ether = NetPacket::Ethernet->decode( $pack );	
	$ip = NetPacket::IP->decode( $ether->{'data'} );
	$trans = NetPacket::TCP->decode( $ip->{'data'} );

	# and now to dump the content of the data variable into a file
	print OF $trans->{'data'};

	return 1;
}

sub read_all_packets
{
	my $user_data = shift;
	my $header = shift;
	my $pack = shift;
	my $fcheck;
	my $input;

	# check if we have printed $buffer
	if( $i == $buffer )
	{
		# print out a statement
		print "Read more packets [Y|n]: ";
		$input = <STDIN>;
		chomp( $input );

		if( lc( $input ) eq 'n' )
		{
			# we quit
			print "Not printing out more packets\n";
			exit 0;	
		}	
		else
		{
			# we continue
			$i = 0;
			# clear the screen
			system $^O eq 'MSWin32' ? 'cls' : 'clear';

		}	
	}

	# strip header information
	$ether = NetPacket::Ethernet->decode( $pack );	
	
	# check if IP
	if( $ether->{type} eq 2048 )
	{
		$ip = NetPacket::IP->decode( $ether->{'data'} );

		# check if TCP or UDP
		if( $ip->{'proto'} eq 6 )
		{
			# TCP
			$trans = NetPacket::TCP->decode( $ip->{'data'} );

			# check if we are to dump "all" traffic or just show new connections
			if( $only_syn )
			{
				# we don't care about ECN bits
				$fcheck = $trans->{'flags'} & 0x3f;

				# check if we have a SYN packet
				if( $fcheck == 0x02  )
				{
					print '[',$index,'] ' if $s_index;
					
					print 'TCP ' , $ip->{'src_ip'}  , ':' , $trans->{'src_port'} ,  ' -> ' , $ip->{'dest_ip'} , ':' , $trans->{'dest_port'},"\n";
					# increment both the index variable as well as the (for printing)
					$index++;
					$i++;
				}
			}
			else
			{	
				# we show all connections
				print '[',$index,'] ' if $s_index; 
				print 'TCP ', $ip->{'src_ip'}  . ':' . $trans->{'src_port'} .  ' -> ' . $ip->{'dest_ip'} . ':' . $trans->{'dest_port'},'[',$trans->{'flags'},"]\n";
				# increment both the index variable as well as the (for printing)
				$index++;
				$i++;
			}

	
		}
		#In this version we do not care about packets that are not TCP
		elsif( $ip->{'proto'} eq 17 )
		{
			# UDP
			$trans = NetPacket::UDP->decode( $ip->{'data'} );
			print 'UDP ' . $ip->{'src_ip'}  . ':' . $trans->{'src_port'} .  ' -> ' . $ip->{'dest_ip'} . ':' . $trans->{'dest_port'} . "\n";
		}
		elsif( $ip->{'proto'} eq 1 )
		{
			$trans = NetPacket::ICMP->decode( $ip->{'data'} );
			print 'ICMP ' . $trans->{'data'} . "\n\n\n\n";
		}
		else
		{
			print 'Not TCP nor UDP, perhaps ICMP? Protocol number is: ' . $ip->{'proto'} . "\n";
		}

	}
	else
	{
		print 'Packet is not an IP packet, rather a ' . $ether->{type} . "\n";
	}
}

# a simple sub routine to show 
sub show_version
{
	print $0,' version ',$version, ' copyright 2009, Kristinn Gudjonsson',"\n";
	exit 0;
}

0;

__END__

=pod

=head1 NAME

B<pcapcat> - a simple script to read PCAP file and dump the content of the conversation into a file 

=head1 SYNOPSIS 

B<pcapcat> [-f|--filter PCAP FILTER] -r|--read PCAP_FILE [-a|-all]

B<pcapcat> -w|--write OUTPUTFILE [-a|--all] -d|-dump INDEX

B<pcapcat>[ -v|--version] [-h|--help|-?] 

=head1 OPTIONS

=over 8

=item B<-f|-filter PCAP_FILTER>

Enter a traditional PCAP filter to filter out the content of the file (see man tcpdump for further details about constructing such a filter)

=item B<-r|-read PCAP_FILE>

The PCAP file that the script should read

=item B<-a|-all>

The default behaviour of the script is to only show TCP SYN packets, that is to show entire conversations.  To override this option and provide the possibility to
dump an already started conversation use this option.

=item B<-w|-write FILE>

Use this option to define an output file to dump the content of the TCP stream into.  If the option -d or -dump is used, then this option has to be defined.

=item B<-d|-dump INDEX>

The default behaviour (if the -d option is not used) is to dump information about TCP connections found inside the pcap file.  In the printout an index number is written.
To be able to dump the content of a stream into a file you must first find out the index number and then use the -d INDEX option with that index number to dump that conversation
into a file.

=item B<-v|-version>

Dump the version number of the script to the screen and quit

=item B<-h|-help|-?>

Print this help menu

=back
