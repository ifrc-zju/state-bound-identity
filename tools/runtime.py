"""Locate locally installed tools; never download or contact a public chain."""
import os
import shutil
from pathlib import Path

def executable(name):
    value = os.environ.get(name.upper() + '_BINARY') or shutil.which(name)
    fallback = Path(__file__).resolve().parents[1] / 'environment' / (name + ('.exe' if os.name == 'nt' else ''))
    if not value and fallback.is_file():
        value = str(fallback)
    if not value:
        raise FileNotFoundError(f'Install {name} and set {name.upper()}_BINARY or add it to PATH; see README.md')
    return value
