#!/bin/sh

# Which remote branch to base the local allmerged branch on
GIT_REMOTEBRANCH=origin/allmerged

# Local name for the allmerged branch
GIT_BRANCH=allmerged-$(date +%Y-%V)

# Revert any possible changes to version.m4 - ignore errors
(git diff version.m4 | git apply -R) 2> /dev/null

# Check if we have a local allmerged branch
if [ -f .git/refs/heads/${GIT_BRANCH} ]; then
    # We do ... drop it
    echo "Dropping old ${GIT_BRANCH}"
    git checkout master 2> /dev/null
    git branch -D ${GIT_BRANCH}
fi

# Check out the remote branch locally
echo "Checking out ${GIT_REMOTEBRANCH} to ${GIT_BRANCH}"
git checkout -b ${GIT_BRANCH} ${GIT_REMOTEBRANCH}

# Get a short version of the last git commit in this branch
GIT_REV=$(git rev-list ${GIT_BRANCH} -1 | cut -b-12)

# Update the version.m4 with the $GIT_REV as OpenVPN version
# Use the version.m4 from the master branch
echo "Updating version.m4"
GIT_VERSIONM4=$(git ls-tree master version.m4 | awk '{print $3}')
git cat-file blob ${GIT_VERSIONM4} | \
    sed "s#define(PRODUCT_VERSION,\[.*\])#define\(PRODUCT_VERSION,\[testing-${GIT_REV}]\)\]#" > version.m4

# Do autotools stuff
echo "Running autotools"
autoreconf -i

