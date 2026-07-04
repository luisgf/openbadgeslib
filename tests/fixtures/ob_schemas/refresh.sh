#!/bin/sh
# Re-fetch the official 1EdTech OB 3.0 JSON Schemas this directory vendors.
# Run from anywhere; files land next to this script. Review `git diff`
# afterwards — a schema change is a spec change (see README.md).
set -eu

base="https://purl.imsglobal.org/spec/ob/v3p0/schema/json"
dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"

for name in \
    ob_v3p0_achievementcredential_schema.json \
    ob_v3p0_profile_schema.json
do
    echo "fetching $name"
    curl -fsS -o "$dir/$name" "$base/$name"
done

echo "done. Review the diff before committing."
