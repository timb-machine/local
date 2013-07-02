#!/usr/bin/perl

#
# IOStack.pl
# Perl(1) script to read stack return address locations of IOS processes
# This is used to get good values for Cisco IOS exploits, such as the one(s) at
# http://www.phenoelit.de/ultimaratio/
#
# Code: FtR of Phenoelit <ftr@phenoelit.de>
# Page: http://www.phenoelit.de/ultimaratio/download.html
#
# Note: In case you got a bunch of Cisco boxes, run it against them and send the
#       output to fx@phenoelit.de. Thanks a bunch.
#
# Use: ./IOStack.pl -d router.your.crappy.net -p LamePass -e EnablePass -v1
#
# $Id: IOStack2.pl,v 1.1.1.1 2013-07-02 23:05:59 timb Exp $
#


use strict;
use Net::Telnet::Cisco;
use Getopt::Std;


# global Vars;
my %CONFIG;
my $CON;
my %RESULT;

CONFIG();

PREPHASE();
GETVERSION(); 
GETTEXTAREA();
GETPROZESSARRAY();
GETPROZESSES();
GETRECPOINTER();
GETSTACKPOINTER();
INSPECTSTACK();
OUTPUT();


sub CONFIG{
my %args;

getopt("vdpelrEut:" ,\%args);

if ($args{'v'}){
        if ($args{'v'}=~m/^\d+/){
	$CONFIG{'VERBOSE'} = $args{'v'};
	}else{   print "Verbose either -v1 or -v2 or -v3 !!! \n";
howto()}

}else{$CONFIG{'VERBOSE'}=0}


if (exists $args{'d'}){
    if ($args{'d'}){$CONFIG{'TARGET'}=$args{'d'}}else { howto()};
}else{     print "NO Destination\n";
	howto()}

if (exists $args{'p'}){
    if ($args{'p'}){$CONFIG{'PASS'}=$args{'p'}}else { howto()};

}else{    print "NO password\n";
howto()}

if (exists $args{'e'}){
    if ($args{'e'}){$CONFIG{'ENABLE_P'}=$args{'e'}}else {$CONFIG{'ENABLE_P'}=""};

}else{  print "NO eneble password \n";
howto()}

if ($args{'l'}){$CONFIG{'CISCOLOG'}=$args{'l'}}else {$CONFIG{'CISCOLOG'}="";};

if ($args{'r'}){$CONFIG{'RETURNFILE'}=$args{'r'}}else {$CONFIG{'RETURNFILE'}="";};

if ($args{'E'}){$CONFIG{'ENABLE_U'}=$args{'E'}}else {$CONFIG{'ENABLE_U'}="";};

if ($args{'u'}){$CONFIG{'USER'}=$args{'u'}}else {$CONFIG{'USER'}="";};

if ($args{'t'}){$CONFIG{'TIMEOUT'}=$args{'t'}}else {$CONFIG{'TIMEOUT'}="100";};


}# sub CONFING

sub PREPHASE{
    printlog("CONNECT\t","1","l");
    $CON=  	Net::Telnet::Cisco->new( 
		Host    =>$CONFIG{'TARGET'},
		Timeout =>$CONFIG{'TIMEOUT'},                                                                   
		Input_Log=>$CONFIG{'CISCOLOG'}) ;
    printlog("OK\n","1","l");

    printlog("LOGIN\t","1","l");
    if ( not $CON->login( Password=>$CONFIG{'PASS'},
		          Name=>$CONFIG{'USER'})
	){ printlog("NO","1","l"); die "\n";  }
    printlog("OK\n","1","l");

    printlog("ENABLE\t","1","l");
    if ( not $CON->enable(Password=>$CONFIG{'ENABLE_P'},
		          Name=>$CONFIG{'ENABLE_U'}) ){ 
	printlog("NO","1","l"); die "\n";  
    }
    printlog("OK\n","1","l");

    printlog("PREPHASE\t","1","l");
    $CON->cmd('terminal length 0');
    printlog("OK\n","1","l");                                     
}# sub PREHASE

sub OUTPUT{
    my @buff ;
    my $buff;
    my ($f,$f2,$f3)=('','','');;    

    

printlog ("
********************************************************************************
IOSSTRING: $RESULT{'GLOB'}{'IOS'}
IMAGE:     $RESULT{'GLOB'}{'IMAGE'}    
MEMORY:    $RESULT{'GLOB'}{'MEM'}    
ARRAY:     $RESULT{'GLOB'}{'ProcessArray'}    


PID   RECORD      STACK       RETURNA     RETURNV    NAME
\n","0","r");
	   
	   

    foreach $buff ( sort keys %{$RESULT{'Proz'}}) {
	printlog( "$RESULT{'Proz'}{$buff}{'Num'}   $RESULT{'Proz'}{$buff}{'Record'}    $RESULT{'Proz'}{$buff}{'Stack'}    $RESULT{'Proz'}{$buff}{'RetrunA'}    $RESULT{'Proz'}{$buff}{'RetrunV'}   $RESULT{'Proz'}{$buff}{'Name'}\n","0","r");

    }
printlog( "********************************************************************************\n","0","r");

    
}# sub OUTPUT
sub GETVERSION{
  my @buff; 	# return Buffer for Router Output
  my @buff2; 	# interrim Buffer
  my $err;   	# error buffer

  printlog("ANALYSE VERSION\t","1","l");    
  @buff= $CON->cmd('show version');

  # get the IOS Version 
  @buff2= grep (/^IOS/, @buff);
  chomp @buff2;
  # check if result is as execpted   
  if (not scalar(@buff2) == 1) { $err="1"}
  $RESULT{'GLOB'}{'IOS'} = $buff2[0];

  # get the image name 
  @buff2= grep (/^System image file/, @buff);
  chomp @buff2;
  # check if result is as execpted   
  if (not scalar(@buff2) == 1) { $err="1"}
  ($RESULT{'GLOB'}{'IMAGE'} = $buff2[0])=~s/.+?"(.+?)".*/$1/;

  # get the memory  
  @buff2= grep (/^cisco/, @buff);
  chomp @buff2;
  # check if result is as execpted   
  if (not scalar(@buff2) == 1) { $err="1"}
  ($RESULT{'GLOB'}{'MEM'} = $buff2[0])=~s/.+?(\d+?K\/\d+?K).*/$1/;


  # Final Error check
  if ($err){ printlog("NOPE\nStrange \"show version\" output","1","l");  die "\n" ;  }
  printlog("OK\n","1","l")
}# sub GETVERSION


sub GETTEXTAREA{
  my @buff; 	# return Buffer for Router Output
  my @buff2; 	# interrim Buffer
  my $err;   	# error buffer

    printlog("TEXTAREA\t","1","l");
    @buff = $CON->cmd( 	String => 'show region',
			Prompt => '/text/',
			Timeout => "10");
    if ($buff[-1]=~m/(0x\w{8}).*?(0x\w{8})/){
	$RESULT{'GLOB'}{'Text'}{'Start'}= $1; 
	$RESULT{'GLOB'}{'Text'}{'End'}=$2;
    }else{
      $err="1"; 
    }#f ($buff[-1]=~m/(0x\w{8}).*?(0x\w{8})/)


    $CON->buffer_empty();
    if ($err){ printlog("NOPE\nStrange \"show region\" output","1","l");  die "\n" ;  }
    printlog("OK\n","1","l")
}# sub GETTEXTAREA

sub GETPROZESSARRAY{
  my @buff; 	# return Buffer for Router Output
  my @buff2; 	# interrim Buffer
  my $err;   	# error buffer

    printlog("PROZESS ARRAY\t","1","l"); 
    @buff = $CON->cmd('show memory processor allocating-process');                      
    @buff2 = grep (/Process Array/,@buff);    
      
    if (scalar(@buff2) == 1){
        # reduce spaces
	$buff2[0] =~s/ +/ /g;
        $buff2[0] =~s/^ +//g;
	($RESULT{'GLOB'}{'ProcessArray'},undef)=split (' ',$buff2[0]);
    }else {$err ="1";}
    
    $CON->buffer_empty();
    if ($err){ printlog("NOPE\nStrange \"show memory processor allocating-process\" output","1","l");  die "\n" ;  }
    printlog("OK\n","1","l")

} #sub GETPROZESSARRAY


sub GETPROZESSES{
  my @buff; 	# return Buffer for Router Output
  my @buff2; 	# interrim Buffer
  my $line;	# Buffer
  my $nu;
  my $name;
  my $err;   	# error buffer

   printlog("COL. PROZ\t","1","l");
    @buff = $CON->cmd('show proc cpu');
    chomp (@buff);
    @buff= grep(/^ *?\d/,@buff);
    foreach $line (@buff){
	$line  =~s/ +/ /g;
	($nu, $name) = (split(/ /,$line,10))[1,9];
	$nu = sprintf ("%3d",$nu);
                                                                                                                                                     
	$RESULT{'Proz'}{$nu}{'Name'}=$name;
	$RESULT{'Proz'}{$nu}{'Num'}=$nu;
                                                                                                                                              
    }# foreach $l(@buff)      
    $RESULT{'GLOB'}{'Prozesse'}=$nu;                                                       
    $RESULT{'GLOB'}{'ProzesseNU'}= scalar(@buff);

    printlog("$RESULT{'GLOB'}{'ProzesseNU'}\n","1","l");

}#sub GETPROZESSES


sub GETRECPOINTER{
  my @buff; 	# return Buffer for Router Output
  my @buff2; 	# interrim Buffer
  my @pointer;	# all pointer
  my $err;   	# error buffer
  my $buff ;	# buffer
  my $hexv; 	# Hexvalue 
  my $i;	# run var
 # printlog("PROZESS RECORDS\t","1");
  
  $buff= sprintf(
	"0x%x",
	 hex($RESULT{'GLOB'}{'ProcessArray'}) + 51 # 51 = 36 - 40 byte header + 4 byte  padding + 4 number of Proz +4 byte Resverve 
	 + ($RESULT{'GLOB'}{'Prozesse'}*4)                        
	 );                       
  @buff = $CON-> cmd("show memory 0x$RESULT{'GLOB'}{'ProcessArray'} $buff");
  @buff = GETHEX (@buff);

  #find all Elements 
  $hexv= sprintf("%08X",$RESULT{'GLOB'}{'ProzesseNU'});
  $i = 0 ;

  foreach $buff (@buff){
    $i++;

    if ( $buff eq $hexv){
      last;
    }# if ( $buff eq $hexv) 
  }# foreach $buff (@buff)
  if  ($i == scalar(@buff)){ $err="1"}
    
  # remove the beginning 
  @buff = splice (@buff,$i);
  # chop the end 
  @buff = splice (@buff,0,$RESULT{'GLOB'}{'Prozesse'});
  
  # place Value into hash 
  $i=0;
  printlog("\n","2","l");
  foreach $buff (@buff){
    $i++;
    $hexv = sprintf("%3d",$i);
    if (exists $RESULT{'Proz'}{$hexv}){
           $RESULT{'Proz'}{$hexv}{'Record'}= $buff;
	   printlog("$RESULT{'Proz'}{$hexv}{'Name'}\t$buff","2","l");
	   printlog("\n","2","l");	       	   
    }# if (exists $RESULT{'Proz'}{$hexv})
  }# foreach $buff (@buff)

  if ($err) {printlog ("NOPE\nStrange Process Array\n","1","l"); die "\n" }  
#  printlog("OK\n","1");
}#sub GETRECPOINTER


sub GETSTACKPOINTER {
  my @buff; 	# return Buffer for Router Output
  my @buff2; 	# interrim Buffer
  my $buff;	# 
  my $start;	# Hex buffer
  my $end;	# Hex buffer	
  my $err;   	# error buffer
  my $i;	# running Var
       
  foreach $buff ( sort keys %{$RESULT{'Proz'}} ){
    printlog("FINDING PROCESSTACK ".++$i."/$RESULT{'GLOB'}{'ProzesseNU'}\r","1",,"l"); 

    # check if stack pointer <> 0 
    if (hex($RESULT{'Proz'}{$buff}{'Record'})>0){
	# we need the Val of  4 -8 byte after the Stack Arddess
 	$start = sprintf( 
			    "0x%x",
			    hex($RESULT{'Proz'}{$buff}{'Record'})+4);
	$end	=sprintf (
			    "0x%x",
			    hex($RESULT{'Proz'}{$buff}{'Record'})+7);
	$CON->cmd("!$RESULT{'Proz'}{$buff}{'Name'}");
	@buff= $CON->cmd("show memory $start $end");
	@buff2 = GETHEX(@buff);
	
	#make sure that only one pointer came back otherwise we leave it blank
	if ( scalar(@buff2) == 1 ){
	    $RESULT{'Proz'}{$buff}{'Stack'}= $buff2[0];
  	    printlog("\n$RESULT{'Proz'}{$buff}{'Name'}\t$buff2[0]","2",,"l");
	    printlog("\n","2","l");
	}#if ( scalar(@buff2) == 1 )
    }# if (hex($RESULT{'Proz'}{$buff}{'Record'})>0)
  }#foreach $buff ( sort keys %{$RESULT{'Proz'}} )
    printlog("\n","1","l");

} # sub GETSTACKPOINTER

sub INSPECTSTACK{
  my @buff; 	# return Buffer for Router Output
  my @buff2; 	# interrim Buffer
  my $err;   	# error buffer
  my $i;
  my $j;
  my $buff;
  my $start;
  my $end;
  my $line; 	# more buffer
  my $ele;
  my $mem;
  
  foreach $buff ( sort keys %{$RESULT{'Proz'}}){
    printlog("INSPECTING PROCESSTACK ".++$i."/$RESULT{'GLOB'}{'ProzesseNU'}\r","1","l"); 
    $CON->cmd("!$RESULT{'Proz'}{$buff}{'Name'}");
    
    $start= sprintf("0x%x",
		    hex( $RESULT{'Proz'}{$buff}{'Stack'}));
		    	
    $end= sprintf("0x%x",
		    hex( $RESULT{'Proz'}{$buff}{'Stack'})+100 );
  
    @buff = $CON->cmd("show memory $start $end");
    
    SEARCH: foreach $line (@buff){
	($mem,undef) = split (/ /, $line , 2);
	$mem =~s/[ :]//g;
	$j=0;
	@buff2 = GETHEX($line);
	printlog ("\nCHECK: ","2","l");
	foreach $ele (@buff2){
	    printlog ("$ele ","2","l");
	    if ( ( hex($RESULT{'GLOB'}{'Text'}{'Start'}) < hex ($ele)) and ( hex($RESULT{'GLOB'}{'Text'}{'End'}) > hex ($ele)) ){
		$RESULT{'Proz'}{$buff}{'RetrunA'}= sprintf ("%08x",
							hex($mem) + ( ( 4 - scalar(@buff2) + $j ) *4) );
			#				print hex($mem)." + ( ( 4 -". scalar(@buff2)." + $j ) *4) )";
		
		$RESULT{'Proz'}{$buff}{'RetrunV'}=$ele;
		
		printlog ("\nMEM $mem \n","2","l");
#		 + ( $j + 4 - scalar(@buff2))*4,"2");
		last SEARCH;
	    }# if ( ( hex($RESULT{'GLOB'}{'Text'}{'Start'}) < hex ($ele)) and hex($RESULT{'GLOB'}{'Text'}{'end'}) > hex ($ele)) )
	    $j++;
	}# foreach $ele (@buff2)
    }#SEACH: foreach $line ( @buff)
  }#foreach $buff ( sort keys %{$result{'Proz'}})
  printlog("\n","1","l");
}# sub INSPECTSTACK

sub GETHEX{
  my @buff = @_;
  my @buff2;
  my $buff;
  foreach $buff (@buff){
	push (@buff2, grep /^\w{8}$/ , split (/ /,$buff));
  }#foreach $buff (@buff)

  return @buff2;
}#sub GETHEX



sub howto{
    print
#getopt("vdeEupo:" ,\%args);
"Usage:
 $0 Stack readout tool
    -d Destination 
    -p Password [-u Username]
    [-v [1-3]]  
    [-e Enablepassword] [-E Enable User]  
    [-r Outptfile]
	Pleas send this file to FX\@phenoelit.de
    [-l Dumpfile] 
	In case of errors plase send this File to FtR\@phenoelit.de
    [-t Timeout]
";

die "\n";
}


sub printlog{
 my $text = shift;
 my $level = shift;
 my $type = shift;
 my @log;
 my $i;
 if ($CONFIG{'VERBOSE'}>= $level){
    if ($text=~m/\t/){
	@log = split('\t',$text);
	$text='';
	foreach (@log){
	$text.= $_." "x(30-length($_));
	}
    }
  print "$text";


  if ( $CONFIG{'CISCOLOG'}){
    $text=~s/\r/\n/g;
    open ( RET , ">>",$CONFIG{'CISCOLOG'});
    print RET "$text";
    close RET;
  }

  if ( $CONFIG{'RETURNFILE'} and $type eq "r"){
    $text=~s/\r/\n/g;
    open ( RET , ">>",$CONFIG{'RETURNFILE'});
    print RET "$text";
    close RET;
  }
 
 }
}# sub printlog

