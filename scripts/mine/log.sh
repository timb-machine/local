#!/bin/sh

script -c "${*}" "/root/${1}.$(date +%Y%m%d%H%M)"
