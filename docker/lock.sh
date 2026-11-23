#!/bin/sh
# Regenerate the image's pinned, hash-checked dependencies, inside the image's own base
# (same Linux, same Python), so that the hashes match what the build downloads:
#
#     sh docker/lock.sh
#
# requirements.lock - what runs in the image (zues-scan[server] and its dependencies)
# build.lock        - what builds ZuesScan's own wheel in the build stage (setuptools)
#
# Review the diff before committing: a changed hash for an unchanged version means the
# file on PyPI is not the one locked before.
set -eu
ROOT="$(cd "$(dirname "$0")/.." && { pwd -W 2>/dev/null || pwd; })"  # pwd -W: Git Bash on Windows
export MSYS_NO_PATHCONV=1  # Git Bash: do not rewrite /src into a Windows path
BASE="$(sed -n 's/^ARG PYTHON_IMAGE=//p' "$ROOT/Dockerfile")"
docker run --rm -v "$ROOT:/src" -w /src "$BASE" sh -euc '
  pip install -q --root-user-action=ignore pip-tools
  export CUSTOM_COMPILE_COMMAND="sh docker/lock.sh"
  pip-compile --quiet --generate-hashes --extra server --strip-extras --no-emit-index-url \
    --output-file docker/requirements.lock pyproject.toml
  echo "setuptools>=68" > /tmp/build.in
  pip-compile --quiet --generate-hashes --allow-unsafe --no-emit-index-url \
    --output-file docker/build.lock /tmp/build.in
'
