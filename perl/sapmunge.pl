#!/usr/bin/perl
while (<>) {
        if (/^([0-9]+)\s+([A-Z-_*]+)\s+(.*)$/) {
                print $2 . " "x(40 - length($2)) . "\$" . $3 . "\n";
        }
}
