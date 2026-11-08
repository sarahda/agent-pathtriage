#!/usr/bin/env bash
# Build the agent zips and put them in the lab bucket.
#
# Two artifacts. benign.py is what the victims are deployed with. planted.py is
# what an attacker installs in their place: it reports the role it was handed
# and reads the object the attacker points it at.
#
# The bucket is not written down here. It is passed in or discovered.
set -euo pipefail

BUCKET="${1:-${APT_BUCKET:-}}"
if [ -z "$BUCKET" ]; then
  BUCKET=$(aws s3api list-buckets \
    --query 'sort_by(Buckets,&CreationDate)[?starts_with(Name,`apt-takeover-`)].Name | [-1]' \
    --output text)
fi
[ -n "$BUCKET" ] && [ "$BUCKET" != "None" ] || { echo "no apt-takeover-* bucket found; pass one as \$1"; exit 1; }
echo "bucket: $BUCKET"

HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

for variant in benign planted; do
  SRC="$HERE/agent-src/$variant.py"
  [ -f "$SRC" ] || { echo "missing $SRC"; exit 1; }
  mkdir -p "$WORK/$variant"
  # the runtime's entryPoint is main.py, so each variant is zipped under that name
  cp "$SRC" "$WORK/$variant/main.py"
  ( cd "$WORK/$variant" && zip -q -r "../$variant.zip" main.py )
  aws s3 cp "$WORK/$variant.zip" "s3://$BUCKET/code/$variant.zip" --content-type application/zip
done

echo
aws s3 ls "s3://$BUCKET/code/"
