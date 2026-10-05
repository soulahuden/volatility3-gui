@echo off
rem Starts the Volatility 3 GUI on Windows (needs Python 3 and: pip install pefile pycryptodome capstone yara-python)
cd /d "%~dp0"
start "" pythonw vol_gui.py
