#!/usr/bin/env bash
# Image-side operations, with no YAML parsing or container-engine dependencies.
# Invoked from the generated Containerfile as: hb-rootfs reset|check-base|policy|cleanup ROOT [DISTRO|POLICY]
set -euo pipefail

hb_rootfs_error() { printf 'hb-rootfs: %s\n' "$*" >&2; return 1; }

hb_rootfs_validate() {
    local root="${1:-}" resolved
    case "$root" in
        /*) ;;
        *) hb_rootfs_error "root must be an absolute, disposable directory: '$root'"; return 1 ;;
    esac
    case "$root" in
        /|/bin|/boot|/dev|/etc|/home|/lib|/lib64|/mnt|/opt|/proc|/root|/run|/sbin|/srv|/sys|/tmp|/usr|/var)
            hb_rootfs_error "refusing to operate on protected path '$root'"; return 1 ;;
    esac
    resolved="$(realpath -m -- "$root")" || return 1
    if [[ "$resolved" != "$root" || -L "$root" ]]; then
        hb_rootfs_error "root must not contain symlinks, '..' or redundant separators: '$root'"
        return 1
    fi
}

hb_rootfs_beneath() {
    local root="$1" path resolved
    shift
    for path in "$@"; do
        resolved="$(realpath -m -- "$path")" || return 1
        [[ "$resolved" == "$root/"* ]] || {
            hb_rootfs_error "path escapes the rootfs: $path"; return 1;
        }
    done
}

hb_rootfs_check_base() {
    local root="$1" distro="$2" id version
    # A content-only seed need not contain os-release. When it does, refuse to
    # turn (for example) a UBI 9 RPM database into a UBI 10 root by accident.
    [[ -f "$root/etc/os-release" ]] || return 0
    hb_rootfs_beneath "$root" "$root/etc/os-release" || return 1
    # Parse as data, never source a file supplied by the base image as shell.
    id="$(sed -n 's/^ID=//p' "$root/etc/os-release" | tr -d '\"')"
    version="$(sed -n 's/^VERSION_ID=//p' "$root/etc/os-release" | tr -d '\"')"
    case "$distro:$id:${version%%.*}" in
        hummingbird:hummingbird:*|ubi9:rhel:9|ubi9:ubi:9|ubi10:rhel:10|ubi10:ubi:10) return 0 ;;
        *) hb_rootfs_error "base image ID=$id VERSION_ID=$version does not match requested distro $distro" ;;
    esac
}

hb_rootfs_reset() {
    local root="$1"
    # WHY remove, not mkdir -p: a builder image may already contain this path.
    # Dotfiles and a previous RPM database must never leak into a new image.
    rm -rf -- "$root"
    mkdir -p -- "$root"
}

hb_rootfs_policy() {
    local root="$1" policy="${2:-}" definition backend count=0
    [[ "$policy" =~ ^[A-Z][A-Z0-9_:-]*$ ]] || { hb_rootfs_error "invalid crypto policy '$policy'"; return 1; }
    local definitions="$root/usr/share/crypto-policies/$policy"
    hb_rootfs_beneath "$root" "$definitions" "$root/etc/crypto-policies/state" || return 1
    [[ -d "$definitions" ]] || {
        hb_rootfs_error "$policy definitions missing; install crypto-policies (composite policies need pre-generated definitions)"
        return 1
    }
    if [[ "$policy" == FIPS* ]]; then
        # Do not mark a filesystem FIPS when the provider was never installed.
        local provider="$root/usr/lib64/ossl-modules/fips.so"
        [[ -s "$provider" ]] || provider="$root/usr/lib/ossl-modules/fips.so"
        [[ -s "$provider" ]] || {
            hb_rootfs_error "FIPS provider missing; install openssl-fips-provider and openssl-fips-provider-so"
            return 1
        }
        hb_rootfs_beneath "$root" "$provider" || return 1
    fi
    for definition in "$definitions"/*.txt; do
        [[ -f "$definition" ]] && count=$((count + 1))
    done
    ((count > 0)) || { hb_rootfs_error "no backend definitions for $policy"; return 1; }

    # Drop stale/custom backends too, not only those which happen to be links
    # to DEFAULT. Never follow a base image's backend-directory symlink.
    rm -rf -- "$root/etc/crypto-policies/back-ends"
    mkdir -p "$root/etc/crypto-policies/back-ends" "$root/etc/crypto-policies/state"
    for definition in "$definitions"/*.txt; do
        [[ -f "$definition" ]] || continue
        backend="${definition##*/}"
        # WHY recreate from the selected distro's definitions: inherited bases
        # can have relative links, regular files, or LEGACY (not just DEFAULT)
        # backends. No chroot/foreign-architecture binary is needed here.
        ln -sfn "/usr/share/crypto-policies/$policy/$backend" \
            "$root/etc/crypto-policies/back-ends/${backend%.txt}.config"
    done
    rm -f -- "$root/etc/crypto-policies/config" "$root/etc/crypto-policies/state/current"
    printf '%s\n' "$policy" > "$root/etc/crypto-policies/config"
    printf '%s\n' "$policy" > "$root/etc/crypto-policies/state/current"
}

hb_rootfs_cleanup() {
    local root="$1" database
    hb_rootfs_beneath "$root" "$root/var/cache" "$root/etc" || return 1
    # RPM4 (UBI) and RPM6 (Hummingbird) do not necessarily use the same paths;
    # never create an empty database just because one expected path is absent.
    for database in "$root/usr/lib/sysimage/rpm/rpmdb.sqlite" \
                    "$root/var/lib/rpm/rpmdb.sqlite" \
                    "$root/usr/lib/sysimage/libdnf5/transaction_history.sqlite" \
                    "$root/var/lib/dnf/history.sqlite"; do
        [[ -f "$database" ]] || continue
        hb_rootfs_beneath "$root" "$database" || return 1
        sqlite3 "$database" 'PRAGMA journal_mode = DELETE;'
    done
    rm -rf -- "$root"/var/cache/* "$root/etc/machine-id" \
        "$root/etc/group-" "$root/etc/gshadow-" "$root/etc/passwd-" "$root/etc/shadow-"
}

main() {
    local action="${1:-}" root="${2:-}"
    hb_rootfs_validate "$root" || return 1
    case "$action" in
        reset) hb_rootfs_reset "$root" ;;
        check-base) hb_rootfs_check_base "$root" "${3:-}" ;;
        policy) hb_rootfs_policy "$root" "${3:-}" ;;
        cleanup) hb_rootfs_cleanup "$root" ;;
        *) hb_rootfs_error 'usage: hb-rootfs reset|check-base|policy|cleanup ROOT [DISTRO|POLICY]' ;;
    esac
}
main "$@"
