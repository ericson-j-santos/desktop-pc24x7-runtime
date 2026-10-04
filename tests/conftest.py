from __future__ import annotations

import sys
from pathlib import Path

# Production entry points execute from scripts/, so sibling modules are importable.
# Tests load those entry points via importlib, which does not add scripts/ to sys.path.
SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
scripts_path = str(SCRIPTS)
if scripts_path not in sys.path:
    sys.path.insert(0, scripts_path)
