#!/bin/bash

set -e
ORIG=$PWD

register_binformat() {
    if [ ! -f /proc/sys/fs/binfmt_misc/qemu-aarch64 ]; then
        echo "Q-Emu Bin Format for AARCH64 in not registered."
        echo "  Please run: "
        echo "    docker run --rm --privileged hypriot/qemu-register"
        exit 1
    fi
}

ARCH=arm64v8
echo "Building py-pingu static executable - arch: $ARCH"
#ARCH=x86

if [[ $ARCH == "arm64v8" ]]; then
    register_binformat
fi

if [ -z $1 ]; then
    OUTPUT_PATH="../out/"
else
    OUTPUT_PATH="$1"
fi

echo "OUTPUT_PATH: $PWD/$OUTPUT_PATH"
cd devops/
rm -rf out/
rm -rf src/
mkdir -p out

cp -rfp ../src/ .


DOCKER_IMAGE_NAME=py-pingu-$ARCH

docker build -t $DOCKER_IMAGE_NAME . -f Dockerfile-$ARCH
docker run -it -v $PWD/$OUTPUT_PATH:/output $DOCKER_IMAGE_NAME

echo "Statically linked exectable generated in  $PWD/$OUTPUT_PATH/py-pingu"


