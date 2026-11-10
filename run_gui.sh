#!/usr/bin/env bash
# Starts the Volatility 3 GUI, creating the virtualenv on first use.
set -e
cd "$(dirname "$(readlink -f "$0")")"
if [ ! -x .venv/bin/python ]; then
    python3 -m venv --system-site-packages .venv
    .venv/bin/python -m pip install -q pefile pycryptodome capstone yara-python
fi
# vol-rs is the analysis engine; without it the GUI falls back to vol.py
.venv/bin/python install_vol_rs.py || echo "vol-rs not installed, using vol.py" >&2
exec .venv/bin/python vol_gui.py "$@"
