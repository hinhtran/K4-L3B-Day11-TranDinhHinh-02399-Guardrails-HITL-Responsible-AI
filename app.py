"""
Launcher for VinBank AI Security Arena & Live Debugger
Run with: streamlit run app.py
"""
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent
_SRC = _ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

# Execute UI app
app_file = _SRC / "ui" / "app.py"
with open(app_file, encoding="utf-8") as f:
    code = compile(f.read(), str(app_file), "exec")
    exec(code, globals())
