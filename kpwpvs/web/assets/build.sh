#!/bin/sh
# Build the interface stylesheet.
#
# Run from the repository root. Uses the standalone tailwind cli so no
# node_modules end up anywhere near the runtime image.
set -eu

TAILWIND="${TAILWIND:-tailwindcss}"
"$TAILWIND" \
  --input  kpwpvs/web/assets/app.css \
  --output kpwpvs/web/static/app.css \
  --minify
