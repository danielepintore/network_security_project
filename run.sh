#!/usr/bin/env sh

# Quit upon error
set -e

# Create virtual environment
if [ ! -d "./venv/" ]; then
    python3 -m venv venv
fi

# Activate virtual environment
. ./venv/bin/activate
if [ -n "$VIRTUAL_ENV" ]; then
    echo "Virtualenv is activated: $VIRTUAL_ENV"
else
    echo "Virtualenv is NOT activated"
    echo "The virtual environment could not be activated."
    exit 1
fi

# build tooling for feature extraction from pcap since it is broken in the upstream
cd cicflowmeter
uv sync --active 
cd ..

uv pip install -r requirements.txt

python main.py
