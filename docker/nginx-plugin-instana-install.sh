#!/bin/bash

set -euo pipefail

# === Configuration ===
NGINX_TRACING_VERSION="${1:-1.12.0}"
NGINX_VERSION="${2:-}"
DOWNLOAD_DIR="${DOWNLOAD_DIR:-$HOME/tmp/instana-nginx}"
INSTANA_URL="https://artifact-public.instana.io/artifactory/shared/com/instana/nginx_tracing/${NGINX_TRACING_VERSION}/linux-amd64-glibc-nginx-${NGINX_VERSION}.zip"

# Debug mode
DEBUG=${DEBUG:-0}
[[ "$DEBUG" -eq 1 ]] && set -x

# === Logging ===
log() { echo "[+] $*" >&2; }
warn() { echo "[!] $*" >&2; }
die() { echo "[ERROR] $*" >&2; exit 1; }

# === Validate inputs ===
[[ -z "$NGINX_VERSION" ]] && die "NGINX_VERSION must be provided as second argument."
[[ -z "${INSTANA_DOWNLOAD_KEY:-}" ]] && die "INSTANA_DOWNLOAD_KEY environment variable is required."

# === Auto-detect NGINX binary and configuration ===
detect_nginx() {
  local nginx_bin=""

  # 1. Try 'which nginx'
  nginx_bin=$(which nginx 2>/dev/null || true)
  [[ -n "$nginx_bin" && -x "$nginx_bin" ]] && { log "Found nginx via which: $nginx_bin"; echo "$nginx_bin"; return; }

  # 2. Try common paths
  local search_paths=(
    "/usr/sbin/nginx"
    "/usr/local/nginx/sbin/nginx"
    "/opt/nginx/sbin/nginx"
    "/opt/nginx/bin/nginx"
    "/bin/nginx"
    "/usr/bin/nginx"
  )
  for p in "${search_paths[@]}"; do
    [[ -x "$p" ]] && { log "Found nginx: $p"; echo "$p"; return; }
  done

  # 3. Fallback: search in /tmp/null/rootfs (container image context)
  if [[ -d "/tmp/null/rootfs" ]]; then
    nginx_bin=$(find /tmp/null/rootfs -type f -name nginx -executable 2>/dev/null | head -n 1 || true)
    [[ -n "$nginx_bin" ]] && { log "Found nginx in rootfs: $nginx_bin"; echo "$nginx_bin"; return; }
  fi

  die "NGINX binary not found. Install nginx or adjust search paths."
}

# === Extract NGINX prefix, modules, and conf paths from nginx -V ===
parse_nginx_v() {
  local nginx_bin="$1"
  local output
  output=$("$nginx_bin" -V 2>&1) || die "Failed to run: $nginx_bin -V"

  local prefix modules_path conf_path

  # Use sed instead of grep -oE (more portable)
  prefix=$(echo "$output" | sed -n 's/.*--prefix=\([^ ]*\).*/\1/p' | head -n1)
  [[ -z "$prefix" ]] && prefix="/usr/local/nginx"

  modules_path=$(echo "$output" | sed -n 's/.*--modules-path=\([^ ]*\).*/\1/p' | head -n1)
  conf_path=$(echo "$output" | sed -n 's/.*--conf-path=\([^ ]*\).*/\1/p' | head -n1 | sed 's|/nginx.conf$||')

  # Fallbacks
  [[ -z "$modules_path" ]] && modules_path="${prefix}/modules"
  [[ -z "$conf_path" ]] && conf_path="${prefix}/conf"

  echo "$prefix|$modules_path|$conf_path"
}


# === Detect OpenSSL version ===
detect_openssl_version() {
  local nginx_bin="$1"
  local version
  version=$("$nginx_bin" -V 2>&1 | grep -oP 'OpenSSL \K[0-9]+\.[0-9]+' | head -n 1 || echo "")
  [[ -z "$version" ]] && die "Could not detect OpenSSL version from nginx -V"
  echo "$version"
}

# === Main ===
main() {
  log "Starting Instana NGINX tracing module installation..."

  # === Step 1: Detect NGINX binary ===
  NGINX_BIN=$(detect_nginx)
  log "Using NGINX binary: $NGINX_BIN"

  # === Step 2: Parse nginx -V for paths ===
  IFS='|' read -r NGINX_PREFIX MODULES_DIR_BASE CONF_DIR_BASE <<< "$(parse_nginx_v "$NGINX_BIN")"
  log "NGINX prefix: $NGINX_PREFIX"
  log "Modules dir (base): $MODULES_DIR_BASE"
  log "Conf dir (base): $CONF_DIR_BASE"

  # === Handle rootfs overlay (e.g., buildah, image build) ===
  ROOTFS_PREFIX=""
  if [[ "$NGINX_BIN" == /tmp/null/rootfs/* ]]; then
    ROOTFS_PREFIX="/tmp/null/rootfs"
    NGINX_BIN="${NGINX_BIN#/tmp/null/rootfs}"
    MODULES_DIR_BASE="${MODULES_DIR_BASE#/tmp/null/rootfs}"
    CONF_DIR_BASE="${CONF_DIR_BASE#/tmp/null/rootfs}"
    log "Detected rootfs overlay: $ROOTFS_PREFIX"
  fi

  # === Final paths ===
  MODULES_DIR="${ROOTFS_PREFIX}${MODULES_DIR_BASE}"
  CONF_DIR="${ROOTFS_PREFIX}${CONF_DIR_BASE}/modules"
  CONF_FILE="${CONF_DIR}/instana.conf"

  log "Final modules dir: $MODULES_DIR"
  log "Final conf dir: $CONF_DIR"
  log "Config file: $CONF_FILE"

  # === Create directories ===
  mkdir -p "$DOWNLOAD_DIR" "$MODULES_DIR" "$CONF_DIR"
  cd "$DOWNLOAD_DIR"

  # === Download ===
  log "Downloading Instana NGINX tracing module v${NGINX_TRACING_VERSION} for NGINX ${NGINX_VERSION}..."
  curl -fsSL -u "_:$INSTANA_DOWNLOAD_KEY" "$INSTANA_URL" -o nginx-tracing.zip \
    || die "Failed to download module. Check NGINX_VERSION and INSTANA_DOWNLOAD_KEY."

  # === Extract ===
  log "Extracting archive..."
  unzip -o nginx-tracing.zip || die "Failed to extract ZIP."

  # === Detect OpenSSL ===
  OPENSSL_VERSION=$(detect_openssl_version "${ROOTFS_PREFIX}${NGINX_BIN}")
  log "Detected OpenSSL version: $OPENSSL_VERSION"

  SSL_FILE_PATTERN=""
  if [[ "$OPENSSL_VERSION" == 1.1* ]]; then
    SSL_FILE_PATTERN="ssl1.1x"
  elif [[ "$OPENSSL_VERSION" == 3.* ]]; then
    SSL_FILE_PATTERN="ssl3x"
  else
    warn "Unknown OpenSSL version: $OPENSSL_VERSION. Defaulting to ssl3x."
    SSL_FILE_PATTERN="ssl3x"
  fi
  log "Using SSL pattern: $SSL_FILE_PATTERN"

  # === Install .so files ===
  log "Installing modules..."
  > "$CONF_FILE"  # Clear config

  declare -A installed_modules

  for file in glibc-*.so; do
    [[ -f "$file" ]] || continue

    # Skip mismatched SSL modules
    if [[ "$file" == *ssl1.1x.so ]] && [[ "$SSL_FILE_PATTERN" != "ssl1.1x" ]]; then
      log "Skipping $file (OpenSSL 1.1.x not detected)"
      continue
    elif [[ "$file" == *ssl3x.so ]] && [[ "$SSL_FILE_PATTERN" != "ssl3x" ]]; then
      log "Skipping $file (OpenSSL 3.x not detected)"
      continue
    fi

    # Clean filename
    CLEAN_NAME=$(echo "$file" | sed -E 's/^glibc-//; s/nginx-[0-9.]+-//')
    DEST_FILE="${MODULES_DIR}/${CLEAN_NAME}"

    # Avoid duplicates
    [[ -f "$DEST_FILE" ]] && { warn "Module already exists: $DEST_FILE, skipping."; continue; }

    log "Installing: $file → $DEST_FILE"
    mv "$file" "$DEST_FILE"

    # Add to config only if it's the main tracing module
    if [[ "$CLEAN_NAME" == ngx_http_ot_module.so ]]; then
      RUNTIME_PATH="${DEST_FILE#$ROOTFS_PREFIX}"
      echo "load_module $RUNTIME_PATH;" >> "$CONF_FILE"
      log "Added to config: load_module $RUNTIME_PATH;"
    fi

    installed_modules["$CLEAN_NAME"]=1
  done

  # === Final check ===
  if [[ ! -f "$CONF_FILE" ]] || ! grep -q "load_module" "$CONF_FILE"; then
    die "Failed to generate valid instana.conf — no tracing module found."
  fi

  log "Instana NGINX tracing installed successfully!"
  log "   Modules: $MODULES_DIR"
  log "   Config:  $CONF_FILE"
  log ""
}

# === Run ===
main "$@"