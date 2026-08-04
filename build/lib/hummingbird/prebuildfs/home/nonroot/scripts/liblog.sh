#!/bin/bash

# Library for logging functions

# Functions

########################
# Print to STDERR or STDOUT based on log level
# Arguments:
#   Log level
#   Message to print
# Returns:
#   None
#########################
stderr_print() {
    local level="${1}"
    local message="${2}"
    local bool="${QUIET:-false}"
    shopt -s nocasematch
    if ! [[ "$bool" = 1 || "$bool" =~ ^(yes|true)$ ]]; then
        if [[ "$level" = "error" ]]; then
            printf "%b\\n" "${message}" >&2
        else
            printf "%b\\n" "${message}"
        fi
    fi
}

########################
# Log message in JSON format
# Arguments:
#   Log level
#   Message to log
# Returns:
#   None
#########################
log() {
    local level="${1}"
    local message="${2}"
    local timestamp
    timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    stderr_print "${level}" "{\"level\": \"${level}\", \"ts\": \"${timestamp}\", \"msg\": \"${message}\"}"
}

########################
# Log an 'info' message
# Arguments:
#   Message to log
# Returns:
#   None
#########################
info() {
    log "info" "${*}"
}

########################
# Log a 'warn' message
# Arguments:
#   Message to log
# Returns:
#   None
#########################
warn() {
    log "warn" "${*}"
}

########################
# Log an 'error' message
# Arguments:
#   Message to log
# Returns:
#   None
#########################
error() {
    log "error" "${*}"
}

########################
# Log a 'debug' message
# Globals:
#   DEBUG
# Arguments:
#   Message to log
# Returns:
#   None
#########################
debug() {
    local bool="${DEBUG:-false}"
    shopt -s nocasematch
    if [[ "$bool" = 1 || "$bool" =~ ^(yes|true)$ ]]; then
        log "debug" "${*}"
    fi
}

########################
# Indent a string
# Arguments:
#   $1 - string
#   $2 - number of indentation characters (default: 4)
#   $3 - indentation character (default: " ")
# Returns:
#   None
#########################
indent() {
    local string="${1:-}"
    local num="${2:?missing num}"
    local char="${3:-" "}"
    # Build the indentation unit string
    local indent_unit=""
    for ((i = 0; i < num; i++)); do
        indent_unit="${indent_unit}${char}"
    done
    # shellcheck disable=SC2001
    # Complex regex, see https://github.com/koalaman/shellcheck/wiki/SC2001#exceptions
    echo "$string" | sed "s/^/${indent_unit}/"
}
