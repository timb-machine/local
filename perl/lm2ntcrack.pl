#!/usr/bin/perl
##################################################################################

##################################################################################
# Microsoft NT Hash cracker from LM Password
#
# Yannick Hamon <yannick.hamon@xmcopartners.com>
# IT Security Consultant
# Xmco Partners | Security Research Labs
# http://www.xmcopartners.com
#
# For educational purpose and XMCO PARTNERS audits.
#
# THIS SOFTWARE IS MADE AVAILABLE "AS IS", AND THE AUTHOR DISCLAIMS ALL
# WARRANTIES, EXPRESS OR IMPLIED, WITH REGARD TO THIS SOFTWARE, INCLUDING
# WITHOUT LIMITATION ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE, AND IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER
# RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF
# CONTRACT, TORT (INCLUDING NEGLIGENCE) OR STRICT LIABILITY, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#
#
# References : 
#		Remediations from MICROSOFT TECHNET : Prevent Windows from storing LM HASH
# 		* Windows 95 and NT4 : 		 	http://support.microsoft.com/kb/147706
#		* Windows 2000, XP and 2003 : 	http://support.microsoft.com/kb/299656
#
#
# Release 1.1 : Bug fix on string comparison - report by Ignacio Hernandez
# Release 1.2 : Bug fix on string comparison when NTHASH is lowercase - report by Yannick Hamon
#
##################################################################################

use strict;
use Getopt::Long;
require Digest::MD4;

############################# GLOBAL VARS #########################

my $SCRIPT_NAME 			= $0; 			# Pogram Name
my $VERSION 				= '1.2'; 		# Release 
my $PUBLISH_DATE			= 'July 2009';	# Published date

my $LM_PASSWORD 			= '';			# Clear text LM Password
my $NT_HASH 				= '';			# NT HASH
my $INPUT_FILE 				= '';			# John Output Filename
my $USER					= '';			# Username
my @DICO 					= ();			# Generated Wordlist

my $IS_HELP 				= 0;			# Print Help message
my $IS_VERBOSE 				= 0;			# Print [INFO] messages
my $IS_QUIET 				= 0;			# Print only John output
my $IS_PRINT				= 0;			# Print DICO on STDOUT
my $IS_INPUT_FILEPROCESS 	= 1;			# Input from john (-f option) or STDIN (-l and -n options)



############################# INIT #################################

####
# Print Banner
printBanner();

####
# Load parameters given to the program					
loadParameters();							

####
# Check for -h option, if set : print usage and exit
if ( $IS_HELP ) {
	printUsage();							
	exit 1;	
}

############################# MAIN #################################

####
# UpperCase the NTHASH
$NT_HASH=uc($NT_HASH);


####
# Check for -n and -l options, if set : unique password cracking
if ( length($NT_HASH) == 32 && length($LM_PASSWORD) > 0 ) { 
	$IS_INPUT_FILEPROCESS = 0;	
}

####
# Single Password Cracking			
if ( !$IS_INPUT_FILEPROCESS ) {
	generateDictionaryFromLMpassword($LM_PASSWORD);
	if ( $IS_PRINT ) {
		printCurrentDico();	
	}
	crackNTpasswordFromDictionary($LM_PASSWORD,$NT_HASH);
}
####
# "John the Ripper" Output File Cracking
# ex : john --show myDump > myOutputFile	
elsif ( $IS_INPUT_FILEPROCESS && -e $INPUT_FILE ) {
	my $count = 0;							# Count NT cracked password
	
	####
	# Read each line of John Output File 
	open (INPUT_FILE, $INPUT_FILE);			

	while (my $line = <INPUT_FILE>) {
		chomp($line);
		####
		# Check for comments line in input file
		next if ( $line =~ /\d+\spassword hashes cracked.\s\d+\sleft/ || length($line) == 0);
		####
		# Parsing "John the Ripper" ouput line
		# LM PASSWORD NOT CRACKED
		if ( $line =~ /(.+):(.*\?\?\?\?.*):\d+:.+:::/ ){
				$USER = $1;
				$LM_PASSWORD = $2;
				print STDERR "[ERROR CRACKED] [".$USER."] LM PASSWORD ".$LM_PASSWORD." NOT CRACKED\n\n";
				next;
		}
		####
		# Parsing "John the Ripper" ouput line
		# NO LM PASSWORD 
		elsif ( $line =~ /(.+):NO PASSWORD:\d+:.+:::/ ){
				$USER = $1;
				print STDERR "[ERROR CRACKED] [".$USER."] NO LM PASSWORD\n\n";
				next;
		}
		####
		# Parsing "John the Ripper" ouput line
		# ex: administrator:AZERTY123$:1234:204BACE8FEA2A28936EF6BE73AEFA8EA:::
#		elsif ( $line =~ /([\w,\d,_,\-,',\&,\(,\)]+):(.+):\d+:([\w,\d]{32}):::/ ){
		elsif ( $line =~ /([^:]+):(.+):\d+:([\w,\d]{32}):::/ ){
			$USER = $1;
			$LM_PASSWORD = $2;
			$NT_HASH = $3;
			
			if ( length($NT_HASH) == 32 && length($LM_PASSWORD) > 0 ) {
				generateDictionaryFromLMpassword($LM_PASSWORD);
				if ( $IS_PRINT ) {
					printCurrentDico();	
				}
				if ( crackNTpasswordFromDictionary($LM_PASSWORD,$NT_HASH) ) {
					$count++;	
				}				
			}
			else {
				print STDERR "[ERROR INPUT FILE] Invalid input : \"".$LM_PASSWORD."::".$NT_HASH."\"\n";
			}	
		}
		else {
			print STDERR "[ERROR INPUT FILE] Invalid input : \"".$line."\"\n => Line must match USER:LM_CLEAR_PASS:UID:NT HASH:::\n";
		}
	}
	
	close (INPUT_FILE);
	
	####
	# If verbose, print $count
	if ( !$IS_QUIET ) {
		print "[INFO] ".$count." NT passwords have been cracked\n\n";	
	}
}
####
# Only print Wordlist for a given password and exit	
elsif ( length($LM_PASSWORD) > 0 && $IS_PRINT ) {
	generateDictionaryFromLMpassword($LM_PASSWORD);
	printCurrentDico();
	exit 1;	
}
####
# ERROR : Invalid parameters
else {
	printSTDERR();
}



############################# FUNCTIONS #################################


#########################################################################
# Read each word of the Wordlist
# Then, generate its NT MD4 hash
# Finally test generated NT MD4 with given hash
# Stop iteration if matched
#########################################################################
sub crackNTpasswordFromDictionary($;$) {	
	my $current_hash = pop(@_);
	my $current_lm = pop(@_);
	chomp($current_lm);
	chomp($current_hash);
	
	if (!$IS_QUIET){
		print "[INFO] : Crack NT password from \"".$current_lm."\" and NT HASH \"".$current_hash."\"\n";
	}
	
	####
	# Try to crack NT password with the generated dictionary
	my $isCracked=0;
	foreach my $pass (@DICO) {
		####
		# If match, print result to STDOUT
		if ( NTHash($pass) eq $current_hash ) {
			if ( length($USER) > 0 ) {
				print "[CRACKED] [".$USER."] ".$current_lm." => ".$pass."\n\n";
			}
			else {
				print "[CRACKED] ".$current_lm." => ".$pass."\n\n";
			}	
			$isCracked = 1;
			last;
		}
	}
	
	####
	# If no password cracked, print ERROR to STDERR
	if ( !$isCracked ) {
			print STDERR "[ERROR CRACK] LM PASSWORD \"".$current_lm."\" DOES NOT MATCH NT HASH \"".$current_hash."\"\n\n";
			return 0;
	}
	
	return 1;
}

#########################################################################
# Generate dictionary from a given LM Password
#########################################################################
sub generateDictionaryFromLMpassword($) {
	my $pass = pop(@_);
	chomp($pass);

	@DICO 		  = ();
	my @upperCase = split(//,uc($pass));
	my @lowerCase = split(//,lc($pass));

	####
	# Determine if LM PASSWORD contains Integers or Special Chars
	# Note : These characters are not case sensitive
	my $charID = 0;
	my %offsetPassword = ();
	foreach my $char (@upperCase) {
		if ( isLMspecialChar($char) ) {
			$offsetPassword{$charID}=$char;
		}
		$charID++;
	}
	my $nbSpecialChars = scalar keys(%offsetPassword);
		
	####
	# Estimated Wordlist length	
	my $lenPass = length($pass); 		
	my $nbWord = 0;	
	if ($nbSpecialChars == 0) {
		$nbWord = 2**$lenPass;
	}
	else {
		$nbWord = 2**($lenPass-$nbSpecialChars);
	}
	
	####
	# Print verbose information concerning Wordlist generation	
	if ( !$IS_QUIET && $IS_VERBOSE ) {
		if ($nbSpecialChars == 0) {
			print "[INFO] : \"".$pass."\" has ".$lenPass." character(s)\n";
		}
		else {
			print "[INFO] : \"".$pass."\" has ".$lenPass." character(s) but contains ".$nbSpecialChars." special(s) char(s) and/or integer(s)\n";		 
		}
		print "[INFO] : => ".$nbWord." words will be generated"; 
	}
	
	####
	# Init DICTIONARY ARRAY
	if ( !$IS_QUIET && $IS_VERBOSE ) {
		printProgress("start");
	}
	foreach my $val (1..$nbWord) {
		push(@DICO,'');
	}
	$charID = 0;

	####
	# Generate Dictionary from LM password
	# Personnal Algo... but works very well !!! :0)
	# May be optimised ???
	my $limitRow = $nbWord/2;
	my $previouslimit = $nbWord;
	my $rowLevel = 0;	
	while ( $limitRow >= 1 ) {
		# Test if current char is special char or integer
		if (exists $offsetPassword{$charID} ) {
			for (my $i=0; $i < $nbWord; $i++) {
				$DICO[$i] .= $upperCase[$charID];	
			}
		}
		else {
			$rowLevel = 2**$charID;
			for ( my $j=0; $j < $nbWord; $j+=$previouslimit ) {
				for (my $i=0; $i < $limitRow; $i++) {
					$DICO[$i+$j] .=	$lowerCase[$charID];
					$DICO[$i+$limitRow+$j] .= $upperCase[$charID];
				}
			}	
			$previouslimit = $limitRow;
			$limitRow = $limitRow/2;
		}
		$charID++;
		if ( !$IS_QUIET && $IS_VERBOSE ) {
			printProgress("");
		}	
	}
	####
	# EXCEPTION : IF LAST(S) CHAR(S) IS/ARE LANMAN SPECIAL CHAR(S)
	while ( $charID < $lenPass ) {
		for ( my $i=0; $i < $nbWord; $i++ ) {
			$DICO[$i] .= $upperCase[$charID];	
		}
		$charID++;
	}
	
	if ( !$IS_QUIET && $IS_VERBOSE ) {
		printProgress("stop");
	}	return 1;
}

#########################################################################
# Test if the given character is case sensitive (a-z) or not (0-9;$_...)
#########################################################################
sub isLMspecialChar($) {
    my $char = pop (@_);
    chomp($char);
    
	if ($char!~/[a-z,A-Z]/) {
		return 1;
	}
	else {
		return 0;
	}
}

#########################################################################
# Return NT MD4 hash from given Password
# Code extracted from Benjamin Kuit's Crypt::SmbHash Perl module
# http://search.cpan.org/dist/Crypt-SmbHash/
#########################################################################
sub NTHash($) {
	my $pass = pop(@_);
	my $hex = '';
	my $digest = '';

	$pass = substr(defined($pass)?$pass:"",0,128);
	$pass =~ s/(.)/$1\000/sg;
	eval {
		$digest = new Digest::MD4;
		$digest->reset();
		$digest->add($pass);
		$hex = $digest->hexdigest();
		$hex =~ tr/a-z/A-Z/;
	};
	return $hex;
}

#########################################################################
# Print ERROR Messages to STDERR
#########################################################################
sub printSTDERR() {
	print "\n";
	if (length($LM_PASSWORD) == 0) {
		print STDERR "[ERROR LM PASS] : LM PASSWORD IS NULL !! \n";
		print STDERR "[ERROR LM PASS] : => Use -l option to set the clear LM password\n\n";
	}
	if (!-e $INPUT_FILE && length($NT_HASH) != 32) {
		print STDERR "[ERROR NT HASH] : ".$INPUT_FILE." INPUT FILE NOT FOUND or NO NT HASH!! \n";
		print STDERR "[ERROR NT HASH] : => Use -f (input file) OR -n (NT HASH) option to set the NT hash\n\n";
	}
	if (-e $INPUT_FILE && !$IS_INPUT_FILEPROCESS){
		print STDERR "[ERROR NT HASH] : set only one option between -n=hash or -f=file !! \n";
	}
	print "\nTry $SCRIPT_NAME -h for more help\n\n";
	exit 0;
}

#########################################################################
# Option -v
# Print Wordlist generation progress
#########################################################################
sub printProgress($) {
    my $str = pop (@_);
    chomp($str);
	
	if ($str=~/^start$/) {
		print ' ';
	}
	elsif ($str=~/^stop$/) {
		print " OK !!\n";
	}
	else {
		print ".";
	}
}

#########################################################################
# Option -p
# Print each line of the Wordlist to STDOUT
#########################################################################
sub printCurrentDico() {
	foreach my $word (@DICO) {
		print "[DICO] ".$word."\n";
	}
	return 1;
}

#########################################################################
# Load parameters given to the program
#########################################################################
sub loadParameters() {
    GetOptions (
    	'help|?' => \$IS_HELP, 
    	'file=s' => \$INPUT_FILE, 
    	'verbose' => \$IS_VERBOSE, 
    	'quiet' => \$IS_QUIET,
    	'print' => \$IS_PRINT,
    	'nthash=s' => \$NT_HASH,
    	'lmpass=s' => \$LM_PASSWORD
    ) or (
    	printUsage() && exit 0
    );
    return 1;
}

#########################################################################
# Print program banner to STDOUT
#########################################################################
sub printBanner() {
	print "############################################################################\n";
	print "# NT Password cracker from LM password\n";
	print "# Version : ".$VERSION." - ".$PUBLISH_DATE."\n";
	print '# By Yannick HAMON <yannick.hamon@xmcopartners.com>'."\n";
	print "# Homepage : http://www.xmcopartners.com\n"; 
	print "############################################################################\n";
}

#########################################################################
# Option -h
# Print Usage to STDOUT
#########################################################################
sub printUsage() {
	 print "\nUsage: $SCRIPT_NAME [ -v | -q ] [ -h ] [ -p ] < -l=Clear_LM_Password -n=MY_NT_HASH > | < -f=MY_JOHN_OUTPUT_FILE >\n";
	 print "\t\t-h, --help\t\t\t\t\t\t: This (help) message\n";
	 print "\t\t-v, --verbose\t\t\t\t\t\t: Verbose output (Optionnal)\n";
	 print "\t\t-q, --quiet\t\t\t\t\t\t: No output debug (Optionnal)\n";
	 print "\t\t-p, --print\t\t\t\t\t\t: Print generated DICO from LM PASSWORD (Optionnal)\n";
	 print "\t\t-f=file, --file=file\t\t\t\t\t: Full path to \"John the ripper\" output file (cmd: john --show dumpfile > <file>)\n";
	 print "\t\t-n=hash, --nthash=hash\t\t\t\t\t: NT hash to CRACK (Mandatory with -l option)\n";
	 print "\t\t-l=Clear_Text_LM_Pwd, --lmpass=Clear_Text_LM_Pwd\t: Cracked LM password\n";
	 print "\n";
	 print "Example 1: perl $SCRIPT_NAME -v -f=\"<JOHN-THE-RIPPER OUTPUT FILE>\"\n\n";
	 print "Example 2: john --format=LM --show myDump > ./crackedLM && perl $SCRIPT_NAME -q -f=./crackedLM\n\n";
	 print "Example 3: perl $SCRIPT_NAME -v -l=\"AZERTY123\$\" -n=\"81CD1A1C4CBCE05C0F8D411ACEC7587F\"\n\n";
	 print "Example 4: perl $SCRIPT_NAME -v -l=\"AZERTY123\$\" -p\n\n";
	 return 1;
}
