#!/bin/bash
if [ "$VERSION" == "1.23.4" ]; then
    dnf install -y --setopt install_weak_deps=false --nodocs python3.12 && dnf clean all
    $HOME/tmp/venv.sh
    rm -rf /var/cache/* /var/log/dnf* /var/log/yum.*
fi