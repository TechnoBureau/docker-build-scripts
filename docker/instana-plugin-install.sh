#!/bin/bash

set -euo pipefail
#set -x


# === Configuration ===
NGINX_TRACING_VERSION="${1:-1.12.0}"
NGINX_VERSION="${2}"
DOWNLOAD_DIR="$HOME/tmp"
MODULES_DIR="/tmp/null/rootfs/opt/nginx/modules"
CONF_DIR="/tmp/null/rootfs/etc/nginx/conf/modules"
CONF_FILE="${CONF_DIR}/instana.conf"
INSTANA_URL="https://artifact-public.instana.io/artifactory/shared/com/instana/nginx_tracing/${NGINX_TRACING_VERSION}/linux-amd64-glibc-nginx-${NGINX_VERSION}.zip"

SEARCH_DIRS=("/tmp/null/rootfs/opt/nginx")

# === Ensure required variables are set ===
if [[ -z "$NGINX_VERSION" ]]; then
  echo "Error: NGINX_VERSION must be provided as the second argument."
  exit 1
fi

if [[ -z "$INSTANA_DOWNLOAD_KEY" ]]; then
  echo "Error: INSTANA_DOWNLOAD_KEY environment variable is not set."
  exit 1
fi

# === Create necessary directories ===
mkdir -p "$DOWNLOAD_DIR" "$MODULES_DIR" "$CONF_DIR"
cd "$DOWNLOAD_DIR" || exit 1

# === Download and extract ===
echo "Downloading Instana NGINX tracing module..."
curl -fsSL -u "_:$INSTANA_DOWNLOAD_KEY" "$INSTANA_URL" -o nginx-tracing.zip

echo "Extracting module..."
unzip -o nginx-tracing.zip

# === Detect OpenSSL version used by NGINX ===


# Search for nginx binary
for dir in "${SEARCH_DIRS[@]}"; do
  found=$(find "$dir" -type f -name nginx 2>/dev/null | head -n 1)
  if [[ -n "$found" && -x "$found" ]]; then
    NGINX_BIN="$found"
    break
  fi
done

# Extract OpenSSL version
if [[ -n "$NGINX_BIN" ]]; then
  OPENSSL_VERSION=$("$NGINX_BIN" -V 2>&1 | grep -oP 'OpenSSL \K[0-9]+\.[0-9]+' | head -n 1 )
else
  echo "Error: nginx binary not found in specified directories."
  OPENSSL_VERSION=""
fi


if [[ -n "$OPENSSL_VERSION" && "$OPENSSL_VERSION" == 1.1* ]]; then
  SSL_FILE_PATTERN="ssl1.1x"
else
  SSL_FILE_PATTERN="ssl3x"
fi


# === Process and move .so files ===
echo "Processing .so files..."
> "$CONF_FILE"  # Clear existing conf file

declare -A seen_modules

for file in glibc-*.so; do
  [[ -f "$file" ]] || continue

  # Skip SSL files that don't match the OpenSSL version
  if [[ "$file" == *ssl1.1x.so && "$SSL_FILE_PATTERN" != "ssl1.1x" ]]; then
    continue
  elif [[ "$file" == *ssl3x.so && "$SSL_FILE_PATTERN" != "ssl3x" ]]; then
    continue
  fi

  # Clean up the filename but preserve uniqueness
  CLEAN_NAME=$(echo "$file" | sed -E 's/^glibc-//; s/nginx-[0-9.]+-//')
  DEST_FILE="${MODULES_DIR}/${CLEAN_NAME}"

  
  echo "Installing: $file → $DEST_FILE"
  mv "$file" "$DEST_FILE"

  # Strip rootfs prefix before writing to config
  RUNTIME_DEST_FILE="${DEST_FILE#/tmp/null/rootfs}"

  # Only load the actual NGINX module
  if [[ "$CLEAN_NAME" == *ngx_http_ot_module.so ]]; then
    echo "Adding to config: load_module $RUNTIME_DEST_FILE;"
    echo "load_module $RUNTIME_DEST_FILE;" >> "$CONF_FILE"
  fi


done


echo "All instana modules installed and ${CONF_FILE} generated successfully."
