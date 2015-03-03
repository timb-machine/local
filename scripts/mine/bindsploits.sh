#!/bin/sh

mount --bind /usr/local/sploits /srv/tftp/sploits
mount --bind /usr/local/sploits /srv/ftp/sploits
mount --bind /usr/local/sploits /var/www/html/sploits_static
