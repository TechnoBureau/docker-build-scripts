#!/bin/sh

# This script creates a Python virtual environment, installs dependencies from a requirements.txt file, and copies any additional files.

set -e

setup_python_venv() {
    echo "Setting up Python virtual environment..."

    cd $HOME

    # Create a new virtual environment
    python3 -m venv --copies --upgrade-deps .venv

    # Activate the virtual environment
    source .venv/bin/activate

    # Install dependencies from requirements.txt if it exists
    if [ -f "$HOME/tmp/requirements.txt" ]; then
        pip install -r $HOME/tmp/requirements.txt
    fi

    # Copy additional files from a venv directory if it exists
    if [ -d "$HOME/tmp/venv" ]; then
        cp -r $HOME/tmp/venv/* $HOME/
        chown $USER:0 -R $HOME/
        chmod 750 -R $HOME/
    fi

    # Uninstall pip for security reasons
    pip uninstall -y pip

    # Deactivate the virtual environment
    deactivate
}

setup_python_venv