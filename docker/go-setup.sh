#!/bin/sh
export PATH="$PATH:${HOME}/go-pkg/go/bin"

# WHY `|| exit`: without it a missing ${HOME}/go leaves the rest of the script
# running `go mod init`/`go build` in whatever directory the image build happens
# to be in, which fails confusingly (or worse, succeeds against the wrong tree).
cd "${HOME}/go" || exit 1
go version
go mod init sgo
go mod tidy
go build -ldflags="-s -w" -o "$HOME/bin/sgo" main.go
