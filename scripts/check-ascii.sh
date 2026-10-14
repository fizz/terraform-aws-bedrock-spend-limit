#!/usr/bin/env bash
# Fails on a non-ASCII character in a .tf file outside a comment.
#
# EC2 and ElastiCache reject non-ASCII in description fields outright. Which services
# accept what is inconsistent, and a rejection can surface at apply, when correcting a
# force-new description is more expensive than the original mistake. Write descriptions
# in ASCII from the start.
set -euo pipefail

status=0
while IFS= read -r file; do
  # The C locale treats every byte above 127 as non-printable, on BSD and GNU grep alike.
  hits=$(LC_ALL=C grep -n $'[^[:print:]\t]' "$file" | grep -v '^[0-9]*:[[:space:]]*#' || true)
  if [ -n "$hits" ]; then
    echo "non-ASCII in ${file}:"
    echo "$hits"
    status=1
  fi
done < <(find . -name '*.tf' -not -path '*/.terraform/*')
exit "$status"
