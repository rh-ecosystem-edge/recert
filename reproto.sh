#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

rm -rf "$SCRIPT_DIR/src/protobuf"
mkdir -p "$SCRIPT_DIR/src/protobuf"

OPENSHIFT_API_DIR="${OPENSHIFT_API_DIR:-"$SCRIPT_DIR/../api"}"

pushd OPENSHIFT_API_DIR >/dev/null
find k8s.io -name 'generated.proto' -exec cp --parents {} ~/repos/recert/src/protobuf ';'

for dir in */; do
	if ! [[ "$dir" == "vendor/" || "$dir" == "tests/" || "$dir" == "tools/" ]]; then
        find "$dir" -name 'generated.proto' -exec cp --parents {} ~/repos/recert/src/protobuf ';'
	fi
done

popd >/dev/null
