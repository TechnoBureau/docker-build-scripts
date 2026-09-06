#!/usr/bin/env bash
# Run all offline regressions. No engine, registry credentials or network needed.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${HB_PYTHON:-python3}"
if [[ "$PYTHON" == */* && "$PYTHON" != /* ]]; then
    PYTHON="$(cd "$(dirname "$PYTHON")" && pwd)/$(basename "$PYTHON")"
fi
export HB_PYTHON="$PYTHON"
export PYTHONDONTWRITEBYTECODE=1
if ! "$PYTHON" -c 'import yaml, jinja2' >/dev/null 2>&1; then
    echo 'Tests need PyYAML + Jinja2. Create a venv and set HB_PYTHON to its Python.' >&2
    exit 1
fi
"$ROOT/tests/hummingbird/run-tests.sh"
"$PYTHON" -m unittest discover -s "$ROOT/tests/hummingbird" -p 'test_*.py' -v
"$PYTHON" "$ROOT/tests/test_build_engine.py"
