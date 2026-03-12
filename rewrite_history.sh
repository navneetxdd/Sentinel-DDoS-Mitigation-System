#!/bin/bash
git filter-branch --force --env-filter '
OLD_EMAIL1="149234854+copilot-swe-agent[bot]@users.noreply.github.com"
OLD_EMAIL2="198982749+Copilot@users.noreply.github.com"
CORRECT_NAME="navneetxdd"
CORRECT_EMAIL="navneetnanda12@gmail.com"

if [ "$GIT_COMMITTER_EMAIL" = "$OLD_EMAIL1" ] || [ "$GIT_COMMITTER_EMAIL" = "$OLD_EMAIL2" ]
then
    export GIT_COMMITTER_NAME="$CORRECT_NAME"
    export GIT_COMMITTER_EMAIL="$CORRECT_EMAIL"
fi
if [ "$GIT_AUTHOR_EMAIL" = "$OLD_EMAIL1" ] || [ "$GIT_AUTHOR_EMAIL" = "$OLD_EMAIL2" ]
then
    export GIT_AUTHOR_NAME="$CORRECT_NAME"
    export GIT_AUTHOR_EMAIL="$CORRECT_EMAIL"
fi
' --msg-filter 'sed -E "/[Cc]o-authored-by:.*[Cc]opilot/d; s/[Cc]opilot//g"' --tag-name-filter cat -- --branches --tags
