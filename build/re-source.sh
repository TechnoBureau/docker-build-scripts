#!/usr/bin/env bash
#
# re-source.sh — bulk rename/rebrand helper.
#
# Purpose:      Rename every file whose name contains a token, and rewrite that
#               token inside every text file below the current directory. Used
#               to re-source a vendored tree (e.g. softwareag -> softwareag1).
#
# Usage:        ./re-source.sh            # applies the default token list below
#               ./re-source.sh FROM TO    # apply a single custom replacement
#
# WARNING:      Operates recursively on the CURRENT DIRECTORY and rewrites files
#               in place. Run it inside a checkout you can `git checkout --`,
#               and review `git status` afterwards.
#
# WHY bash (not sh): the NUL-delimited read below (`read -d ''`) is a bash
# extension. The previous `#!/bin/sh` shebang made this script fail on any
# system where /bin/sh is not bash (dash, busybox ash).

set -uo pipefail

me="$(basename "$(test -L "$0" && readlink "$0" || echo "$0")")"
RED='\033[0;31m'
NC='\033[0m'
GREEN='\033[0;32m'

# RenameFiles <from-token> <to-token>
# Renames every file below . whose name contains <from-token>.
RenameFiles() {
    local from="$1" to="$2" file new
    # WHY -print0 / read -d '': filenames in a vendored tree routinely contain
    # spaces; a newline-delimited pipeline renames the wrong things.
    while IFS= read -r -d '' file; do
        new="$(printf '%s' "$file" | sed "s/${from}/${to}/g")"
        [[ "$file" == "$new" ]] && continue
        printf 'Renaming %b%s%b \t into \t %b%s%b\n' "$RED" "$file" "$NC" "$GREEN" "$new" "$NC"
        mv "$file" "$new"
    done < <(find . -name "*${from}*" -print0)
}

# Replace <from-token> <to-token>
# Rewrites <from-token> in every file below . that grep can match, skipping this
# script itself (so re-running it does not rewrite its own token list).
Replace() {
    local from="$1" to="$2"
    # WHY grep -rlI: -I skips binary files, which otherwise get corrupted by sed.
    # WHY the portable in-place edit: `sed -i ''` is BSD-only and exits 2 on GNU
    # sed ("can't read : No such file or directory"), so the previous form did
    # nothing at all on Linux. `-i.bak` + cleanup works on both.
    grep -rlI "$from" . 2>/dev/null | grep -v "$me" | while IFS= read -r target; do
        sed -i.bak -e "s@${from}@${to}@g" "$target" && rm -f "${target}.bak"
    done
}

if [[ $# -eq 2 ]]; then
    RenameFiles "$1" "$2"
    Replace "$1" "$2"
    exit 0
fi

if [[ $# -ne 0 ]]; then
    echo "usage: ${me} [FROM TO]" >&2
    exit 2
fi

# Default re-sourcing token list.
RenameFiles softwareag softwareag1
Replace softwareag softwareag1
Replace SoftwareAG SoftwareAG1
Replace sagadmin sagadmin1
Replace Softwareag Softwareag1
Replace SOFTWAREAG SOFTWAREAG1
