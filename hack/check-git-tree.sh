#!/usr/bin/env bash

RC=0
changes=$(git status --porcelain)
if [ -n "$changes" ]; then
    echo "Unstaged or untracked changes exist:"
    echo "$changes"
    git diff
    RC=1
else
    echo "git tree is clean"
fi

exit ${RC}
