#!/usr/bin/env bash

set -euo pipefail

# the user is set to avoid permission issue during the creation of the 'dist' folder.
# It has to be also into the docker group or it won't be able to use /var/run/docker.sock.
docker run \
    --user $(id -u):$(getent group docker | cut -d: -f3) \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v $HOME/.docker/config.json:$HOME/.docker/config.json \
    -v $(pwd):/go/src/ui-backend \
    -w /go/src/ui-backend \
    -e HOME=/go \
    -e CGO_ENABLED=1 \
    -e UI_BUNDLE_URL=$UI_BUNDLE_URL \
    goreleaser/goreleaser-cross:v1.19.3 $@
