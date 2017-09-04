#!/bin/sh

USERNAME="${1}"
REPONAME="${2}"

curl -u "${USERNAME}" https://api.github.com/user/repos -d "{\"name\": \"${REPONAME}\", \"description\": \"Automatically exported from projects.nth-dimension.org.uk/subversion/${REPONAME}\", \"has_issues\": \"false\", \"has_projects\": \"false\", \"has_wiki\": \"false\"}"
git svn init -s "https://projects.nth-dimension.org.uk/subversion/${REPONAME}" "${REPONAME}"
cd "${REPONAME}" || exit
git svn fetch
git checkout -b develop
git checkout master
git branch -va
git remote add origin "git@github.com:timb-machine/${REPONAME}.git"
git push origin develop
