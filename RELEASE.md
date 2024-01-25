Creating a release
====================

1. Update release date and version in changelog.md and commit.

2. Merge develop into main:
    git checkout develop
    git merge main
    git checkout main
    git merge --no-ff develop

3. Then tag the new release:
    git tag v0.4.0 -a
    <enter something like "Release v0.4.0">
    git push origin v0.4.0

4. Upload new release to pypi:
    rm dist/*
    python -m build
    twine upload dist/dns_exporter*

5. Back to development:
    git checkout develop
    git merge main

6. Then update CHANGELOG.md, commit and push.
