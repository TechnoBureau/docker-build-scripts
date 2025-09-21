#! /bin/bash
# Use the Docker-provided build argument TARGETARCH to automatically detect the architecture
SUPERCRONIC_VERSION=v0.2.30
SUPERCRONIC_URL=https://github.com/aptible/supercronic/releases/download/${SUPERCRONIC_VERSION}/supercronic-linux-${TARGETARCH}
SUPERCRONIC=supercronic-linux-${TARGETARCH}
mkdir -p "${HOME}/common/bin"
# Use conditional logic to select the correct SHA1SUM based on the architecture
curl -fsSLO "$SUPERCRONIC_URL"
chmod +x "$SUPERCRONIC"
mv "$SUPERCRONIC" "${HOME}/common/bin/${SUPERCRONIC}"
ln -s "${HOME}/common/bin/${SUPERCRONIC}" "${HOME}/common/bin/supercronic"
