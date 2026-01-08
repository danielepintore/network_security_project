#!/usr/bin/env sh

# Quit upon error
set -e

if ! command -v uv >/dev/null 2>&1; then
    echo "uv is not installed. Please install it: https://astral.sh/uv"
    exit 1
fi

uv sync
uv run python main.py
