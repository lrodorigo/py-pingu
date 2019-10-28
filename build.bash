#!/bin/bash
if [ -z $1 ]; then
    PATH="../out/"
else
    PATH="$1"
fi

rm -rf devops/out
mkdir -p devops/out
cp -rfp src/ devops/
cd devops/

docker

docker run -it -v $PWD/$PATH:/output




