#!/bin/bash
# shellcheck disable=SC1091

# Load generic libraries
. /opt/nonroot/scripts/liblog.sh

########################
# Run custom initialization scripts
# Arguments:
#   None
# Returns:
#   None
#########################
custom_init_scripts() {
    local custom_init_dir="${INITSCRIPTS_DIR:-${HOME}/docker-entrypoint-initdb.d}"
    if [[ -n $(find "${custom_init_dir}/" -type f -regex ".*\.sh") ]]; then
        info "Loading user's custom files from $custom_init_dir ..."
        local -r tmp_file="/tmp/filelist"
        find "${custom_init_dir}/" -type f -regex ".*\.sh" | sort >"$tmp_file"
        while read -r f; do
            case "$f" in
            *.sh)
                if [[ -x "$f" ]]; then
                    debug "Executing $f"
                    "$f"
                else
                    debug "Sourcing $f"
                    . "$f"
                fi
                ;;
            *)
                debug "Ignoring $f"
                ;;
            esac
        done <$tmp_file
        rm -f "$tmp_file"
    else
        info "No custom scripts in $custom_init_dir"
    fi
}