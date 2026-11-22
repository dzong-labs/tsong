#!/usr/bin/env bash
# Fails unless every commit in the range, $1 (such as origin/main..HEAD),
# is signed off by its author under the Developer Certificate of Origin:
# a Signed-off-by trailer naming the commit's author, as `git commit -s`
# or the prepare-commit-msg hook writes it. Merge commits are skipped.
set -euo pipefail

# CI sets DEPENDABOT_PR=true only on a pull request GitHub says Dependabot
# opened. There, and only there, Dependabot's own commits are exempt: a bot
# can't certify the DCO. A commit's author is free text, so it never
# exempts a commit on its own.
dependabot='dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>'

range="${1:?usage: scripts/dco.sh <revision range>}"
commits=$(git rev-list --no-merges "$range")
if [ -z "$commits" ]; then
  echo "no commits in $range"
  exit 0
fi
unsigned=0
for commit in $commits; do
  author=$(git log -1 --format='%an <%ae>' "$commit")
  if [ "${DEPENDABOT_PR:-}" = true ] && [ "$author" = "$dependabot" ]; then
    continue
  fi
  if ! git log -1 --format='%(trailers:key=Signed-off-by,valueonly)' "$commit" |
      grep -Fxq "$author"; then
    echo "$(git log -1 --format='%h %s' "$commit"): no Signed-off-by: $author"
    unsigned=1
  fi
done
if [ "$unsigned" -ne 0 ]; then
  echo "Sign off each commit with git commit -s, as CONTRIBUTING.md describes." >&2
  exit 1
fi
echo "every commit in $range is signed off"
