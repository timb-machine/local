#! /usr/bin/perl -w

# testing this script:
# dd if=/dev/urandom of=testfile bs=1M count=10
# losetup /dev/loop1 testfile
# cryptsetup luksFormat /dev/loop1 (choose a trivial password)
# ./luks_cracker -d /dev/loop1 -n 98000 < /usr/share/dict/words
#
# when interrupt, cryptsetup may leave the device opened, clean it up with:
#
# dmsetup ls
# dmsetup remove temporary-cryptsetup-2287
#

use Fcntl;
use Getopt::Std;

sub abort {
 print "\n" . join("\n", @_);
 print "\naborting after $i attemps on passphrase $_\n";
 close(PASS); close(CRYPT); exit(1);
}

if (!getopts('cd:n:s:v')) {
    die "invalid syntax\n";
}

$SIG{INT} = sub { abort("interrupted by user"); };

open(PASS, "> pass") || 
    die("can't open tmp pass file: $!");

if ($opt_d) {
    $dev=$opt_d;
} else {
    $dev = "/dev/loop0";
}

if (!$opt_s) {
    $opt_s = 0;
}

print "Attempting to open luks filesystem on $dev\n";

$i = 0;
$rate = 1;
$| = 1;

if ($opt_v) {
    $verbose = "";
} else {
    $verbose = " 2> /dev/null";
}

if (system("cryptsetup isLuks $dev") == 0) {
    print "device seems to be a LUKS device, going ahead\n";
} else {
    die("this doesn't seem to be a LUKS device\n");
}

$crypt_cmd = "cryptsetup --key-file pass luksOpen $dev cracked $verbose";

if ($opt_v) {
    print "cryptsetup: $crypt_cmd\n";
}
$start = time();
while (<>) {
    chop;
    $key = $_;
    $i++;
    # skip requested lines, to allow resuming
    if ($opt_s && $i < $opt_s) {
        next;
    }
    if ($opt_s && $i == $opt_s) {
        # fix time estimates
        $start = time();
    }
    $d = (time() - $start);
    if ($d > 0) {
        $rate = ($i - $opt_s) / $d;
    }
    if ($opt_c) {
        print "\r";
    } else {
        print "\n";
    }
    printf("Attempt: %d", $i);
    if ($opt_n) {
        printf("/".$opt_n);
        printf(" %02.2f%% ", ($i/$opt_n)*100);
    }
    printf (" rate: %02.2f/s", $rate);
    if ($opt_n and $rate) {
        @eta = gmtime($eta = ($opt_n-$i) / $rate);
        if ($eta > 8640) {
            $days = sprintf("%dd", $eta/8640);
        } else {
            $days = "";
        }
        @d = gmtime($d);
        if ($d > 8640) {
            $d_days = sprintf("%dd", $d/8640);
        } else {
            $d_days = "";
        }
        printf(" time/ETA: %s%02d:%02d:%02d/%s%02d:%02d:%02d", $d_days, $d[2], $d[1], $d[0], $days, $eta[2], $eta[1], $eta[0]);
    }
    print PASS $key;
    $pid = open(CRYPT, "$crypt_cmd 2>&1 |");
    if (!defined($pid)) {
        abort("cannot fork: $!");
    }
    if ($pid) {
        $out = "";
        while (<CRYPT>) {
            chop;
            $out .= $_;
        }
        $success = close(CRYPT);
        if ($out =~ /Command failed: Can not access device/) {
            print "\nProblem with the device, trying to recover from error '$out'\n";
            $dms = `dmsetup ls`;
            wait;
            if ($dms =~ /^(temporary-cryptsetup-\d*).*/mi) {
                print "found temp device: $1, trying to cleanup: \n";
                
                my $retry = 0;
                while (!(system("dmsetup remove $1") == 0)) {
                    print "cannot release $1, retrying\n";
                    sleep 1;
                    abort("cannot cleanup $1")
                        if $retry > 5;
                }
            } else {
                abort("cannot find temporary device to cleanup");
            }
        } elsif ($out =~ /unlocked/) {
            wait;
            $success = 1;
            $unsure = 1;
        }
        if ($opt_v) {
            print " '$out'";
        }
    } else {
        open(STDERR, ">&STDOUT");
        exec($crypt_cmd) 
            or abort("can't exec cryptsetup: $!");
    }
    #$success = (system($crypt_cmd) == 0);
    if ($success) {
        print "\nSuccessfully opened filesystem with key '$key'\n";
        print "You can now mount the device with mount /dev/mapper/cracked /mnt\n";
        print "Otherwise, close the device with cryptsetup luksClose /dev/mapper/cracked\n";
        if ($unsure) {
            print "Success was detected based on the following output: $out\n";
            print "That may not be correct\n";
        }
        last;
    }
    truncate(PASS, 0)
        or abort("can't reset file: $!");
    seek(PASS, 0, 0)
        or abort("can't seek: $!");
}
close(PASS);
print "\nKeyspace exhausted, passphrase not in this dictionnary\n" unless ($success);
