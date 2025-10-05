#!/bin/sh
export PATH=$PATH:${HOME}/go-pkg/go/bin

cd ${HOME}/go
go version
go mod init sgo
go mod tidy
go build -ldflags="-s -w" -o $HOME/bin/sgo main.go