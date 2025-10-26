#!/bin/bash
# shellcheck disable=SC1091

# Load generic libraries
. /home/nonroot/scripts/liblog.sh


########################
# Run custom initialization scripts
# Arguments:
#   None
# Returns:
#   None
#########################
custom_init_scripts() {
    local custom_init_dir="${INITSCRIPTS_DIR:-${HOME}/docker-entrypoint-initdb.d}"
    if [[ -d "${custom_init_dir}" ]]; then
        info "Loading user's custom files from $custom_init_dir ..."
        local script_files=()

        # Safely get script files, handling cases where 'find' might not be available or preferred
        if command -v find >/dev/null 2>&1; then
            # Use find for robustness and sorting
            while IFS= read -r -d $'\0' file; do
                script_files+=("$file")
            done < <(find "${custom_init_dir}/" -type f -regex ".*\.sh" -print0 | sort -z)
        else
            # Fallback for environments without 'find' or for simplicity
            # This approach might not sort files consistently across systems
            for file in "${custom_init_dir}"/*.sh; do
                if [[ -f "$file" ]]; then
                    script_files+=("$file")
                fi
            done
            # Sort the array if 'find' was not used
            if command -v sort >/dev/null 2>&1; then
                IFS=$'\n' script_files=($(sort <<<"${script_files[*]}"))
            else
                # 'sort' not available — keep original order
                IFS=$'\n' script_files=(${script_files[*]})
            fi
            unset IFS
        fi

        if [[ ${#script_files[@]} -gt 0 ]]; then
            for f in "${script_files[@]}"; do
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
            done
        else
            info "No custom scripts in $custom_init_dir"
        fi
    else
        info "Custom init directory $custom_init_dir does not exist."
    fi
}
