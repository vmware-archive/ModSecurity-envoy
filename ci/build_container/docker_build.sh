#!/bin/bash

# Temporarily copy files from envoy
BUILD_FILES=`ls $(dirname $0)/../../envoy/ci/build_container/build_container*.sh`
echo "Copying build files from envoy's git submodule: $BUILD_FILES"
for file in $BUILD_FILES; do
    cp $file .
done

cleanup() {
    # Cleanup when finished
    echo "Cleaning up temporary files"
    for file in $BUILD_FILES; do
        rm `basename $file`
    done
}

trap cleanup EXIT

[[ -z "${LINUX_DISTRO}" ]] && LINUX_DISTRO="ubuntu"
[[ -z "${IMAGE_NAME}" ]] && IMAGE_NAME=envoyproxy/envoy-build-"${LINUX_DISTRO}"

docker build -f Dockerfile-${LINUX_DISTRO} -t ${IMAGE_NAME}:$CIRCLE_SHA1 .

