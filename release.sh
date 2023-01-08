#!/bin/sh
# stop on errors
set -e

# the version to be released
NEWVER=$1

# more variables
TAG="v${NEWVER}"
BRANCH="release-${NEWVER}"

# create new release branch based on develop
git checkout -b "${BRANCH}" develop

# open editor to update the changelog
vim CHANGELOG.md

# commit changes
git add CHANGELOG.md
git commit -m "release.sh preparing to tag ${TAG}"

# switch to main branch
git checkout main

# merge release branch into main
set +e
if ! git merge -m "release.sh: Merging ${BRANCH} into main" --no-ff "${BRANCH}"; then
    echo "release.sh WARNING: Automatic merge failed, spawning an interactive shell so you can manually fix the issue"
    echo "Please fix the conflict, then git add, and then git commit, and finally type 'exit' to continue running release.sh"
fi
set -e

# tag the merge commit
git tag -a "${TAG}" -m "release.sh: Tagging ${TAG}"

# release done, switch to develop
git checkout develop

# merge main branch back into develop
git merge -m "release.sh: Merging main branch back into develop" main

# delete release branch
git branch -d "${BRANCH}"

echo "Done. Make sure everything went well and push to github:"
echo "git checkout main"
echo "git push"
echo "git push origin ${TAG}"
echo "git checkout develop"
echo "git push"

