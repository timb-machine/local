#!/usr/bin/perl
#
# $Id: lbb-add.pl,v 1.2 2013-07-02 23:09:12 timb Exp $

=head1 NAME

ldd-admin.pl

=head1 SYNOPSIS


=head1 DESCRIPTION
This add entries to lbb db
Need: DBD:SQLite from sudo apt-get install libdbd-sqlite-perl
http://search.cpan.org/CPAN/authors/id/M/MS/MSERGEANT/DBD-SQLite-1.13.tar.gz

=cut


# Required use modules
use strict;
use DBI;
use File::Slurp;
use Getopt::Long;
use Text::CSV;

my($help);
GetOptions(
	"h|help"	=> \$help,
) || exit(1);

Usage() if $help;
my($infile) = shift(@ARGV) || die ("$0 [option] db fingerprint certificate privatekey\n");
my($db) = $infile;
my($infile) = shift(@ARGV) || die ("$0 [option] db fingerprint certificate privatekey\n");
my($fingerprint_file) = $infile;
my($infile) = shift(@ARGV) || die ("$0 [option] db fingerprint certificate privatekey\n");
my($certificate_file) = $infile;
my($infile) = shift(@ARGV) || die ("$0 [option] db fingerprint certificate privatekey\n");
my($privatekey_file) = $infile;
my($infile) = shift(@ARGV) || die ("$0 [option] db fingerprint certificate privatekey\n");
my($misc_file) = $infile;

# Open $misc_file to gather additional fields for the lbb.db *yuck*
my $csv = Text::CSV->new();
my @columns;
open (CSV, "<", $misc_file) or die $!;
while (<CSV>) {
   if ($csv->parse($_)) {
      @columns = $csv->fields();
      print "@columns\n";
   } else {
      my $err = $csv->error_input;
      print "Failed to parse line: $err";
   }
}
close CSV;

# Connection to DB file created before
my $dbh = DBI->connect("dbi:SQLite:dbname=$db","","",{ RaiseError => 1}) or die $DBI::errstr;

#PrintSelect($dbh,"SELECT SQLITE_VERSION()");
#PrintSelect($dbh,"SELECT id,fingerprint,certificate,key,description from certificates where id<3");
my $id;
my $hw_vendor=$columns[3];
my $hw_model=$columns[4];
my $hw_revision=$columns[5];

# Insert into Hardware Table
my $stmt_hardware = "SELECT id from hardware where vendor='". $hw_vendor . "' and model='" . $hw_model . "' and revision='" . $hw_revision . "'";
$id=SelectID($dbh,$stmt_hardware);
if ($id eq 0) {
   $id=InsertID($dbh,"INSERT INTO hardware (vendor,model,revision) VALUES ('$hw_vendor','$hw_model','$hw_revision')");
   print $id . "\n";
}
my $hw_id = $id;

# Insert into Certificates Table
my $fingerprint = read_file($fingerprint_file);
my $cert = read_file($certificate_file);
my $privatekey = read_file($privatekey_file);

print "Fingerprint: $fingerprint\n";
print "Certificate: $cert\n";
print "Private Key: $privatekey\n";

my $cert_id=InsertID($dbh,"INSERT INTO certificates (fingerprint,certificate,key,description) VALUES ('$fingerprint','$cert','$privatekey','TEST')");

# Insert into Firmware Table
my $fw_vendor=$columns[1];
my $fw_desc =$columns[2];
my $fw_id = InsertID($dbh,"INSERT INTO firmware (device_id,certificate_id,vendor,description) VALUES ('$hw_id','$cert_id','$fw_vendor','$fw_desc')"); 


#$dbh->do("INSERT INTO certificates (fingerprint,certificate,key,description) values ('fingertest1','certtest1','keytest1','desctest1')");

#close connection
undef($dbh);
#$dbh->disconnect();

### Subroutines ###############################################################
sub Usage {
my $usage = qq/Usage:
	$0 [options] file

Options:
    -h, --help	Display this usage message.
/;
print $usage;
exit;
}

# PrintSelect($dbh,$stmt)
#
sub PrintSelect {
   my($h,$stmt) = @_;
   my @fields;
   my $_sth = $dbh->prepare($stmt);
   $_sth->execute();
   while(@fields = $_sth->fetchrow_array()) {
      print join (', ', @fields) ."\n";
   }
   $_sth->finish;
}

sub SelectID {
   my($h,$stmt) = @_;
   my $_id=0;
   my $_sth = $dbh->prepare($stmt);
   $_sth->execute();

   if (my $_ref=$_sth->fetchrow_hashref) {
      $_id=$_ref->{id};
   }
   $_sth->finish;
   return $_id;
}

sub InsertID {
   my($h,$stmt) = @_;
   my $_id=0;

   # Execute the INSERT stmt.
   my $_sth = $h->prepare($stmt);
   $_sth->execute();

   # Store the $id using func method from the Handle
   # Ref: http://souptonuts.sourceforge.net/code/perlExample.pl.html
   $_id=$h->func('last_insert_rowid');

   $_sth->finish;
   return $_id;
}
