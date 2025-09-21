#!/bin/bash

if [[ -n ${PIPELINE_DEBUG} ]]; then
    set -x
fi

SCRIPT_DIR="/shared"
GO_VERSION="1.23.1"
# shellcheck disable=SC1091
cd ${SCRIPT_DIR}
wget https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz >/dev/null 2>&1
tar -xzf go${GO_VERSION}.linux-amd64.tar.gz >/dev/null 2>&1
mkdir -p ${SCRIPT_DIR}/usr/local
mv go ${SCRIPT_DIR}/usr/local/go
echo "export GOROOT=${SCRIPT_DIR}/usr/local/go" >> $BASH_ENV
echo "export GOPATH=${SCRIPT_DIR}/go" >> $BASH_ENV
echo "export PATH=${PATH}:${SCRIPT_DIR}/usr/local/go/bin:${SCRIPT_DIR}/go/bin" >> $BASH_ENV
rm -rf go${GO_VERSION}.linux-amd64.tar.gz