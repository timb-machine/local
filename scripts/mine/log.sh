#!/bin/sh

script -c "echo ${*} && ${*}" "${HOME}/${1}.$(date +%Y%m%d%H%M%S)"
