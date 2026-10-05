#!/usr/bin/env bash
# Starts the Volatility 3 GUI, creating the virtualenv on first use.
set -e
cd "$(dirname "$(readlink -f "$0")")"
if [ ! -x .venv/bin/python ]; then
    python3 -m venv --system-site-packages .venv
    .venv/bin/python -m pip install -q pefile pycryptodome capstone yara-python
fi
exec .venv/bin/python vol_gui.py "$@"
