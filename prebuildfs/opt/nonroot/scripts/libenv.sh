#!/bin/bash

# shellcheck disable=SC1091

# Specify the output file
mkdir -p "${HOME}/scripts/"
output_file="${HOME}/scripts/default-env.sh"

# Regular expression pattern to exclude variable names
exclude_pattern='^(LANG|TERM|OLDPWD|PWD|SHLVL|HOSTNAME|which_declare|container)|[^a-zA-Z0-9_]+|_+$'

# Open the output file for writing
> "$output_file"

# Loop through environment variables and write to the file
while IFS= read -r variable_name; do
    # Check if the variable matches the exclude pattern
    if [[ ! "$variable_name" =~ $exclude_pattern ]]; then
        variable_value="${!variable_name}"
        # Escape backticks in the variable value
        escaped_value="${variable_value//\`/\\\`}"
        escaped_value="${escaped_value//\$/\\\$}"
        escaped_value="${escaped_value//\"/\\\"}"
        echo "export $variable_name=\"$escaped_value\"" >> "$output_file"
    fi
done < <(compgen -e)