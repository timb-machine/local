#!/bin/sh

SSH_ASKPASS="ksshaskpass"
export SSH_ASKPASS

kdialog --msgbox "Insert your key"
ssh-add -c /home/tmb/.ssh/nth-dimension /home/tmb/.ssh/65535-internal /home/tmb/.ssh/65535-external /home/tmb/.ssh/pcsl /home/tmb/.ssh/thanatos /home/tmb/.ssh/coldcut /home/tmb/.ssh/mobile </dev/null
