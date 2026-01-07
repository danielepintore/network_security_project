#!/usr/bin/env sh

set -e

if [ ! -d "./venv/" ]; then
    # no venv
    python3 -m venv venv
fi

. ./venv/bin/activate
if [ -n "$VIRTUAL_ENV" ]; then
    echo "Virtualenv is activated: $VIRTUAL_ENV"
else
    echo "Virtualenv is NOT activated"
    echo "The virtual environment could not be activated."
    exit 1
fi

cd cicflowmeter
uv sync --active 
cd ..

uv pip install -r requirements.txt

python main.py
