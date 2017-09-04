#!/bin/sh

REPONAME="${1}"

cd "${REPONAME}" || exit
git checkout develop
git svn rebase
git push origin develop
