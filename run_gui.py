# Wrapper to launch VaultCat using uv-managed Python.
# Bypasses Windows Device Guard which blocks the venv's copied python.exe.
# Usage: uv-python run_gui.py chat --ui desktop --skip-tls-verify

import site
import sys
import os

# Add venv site-packages with full .pth file processing (for pywin32 etc.)
ROOT = os.path.dirname(os.path.abspath(__file__))
venv_sp = os.path.join(ROOT, ".venv", "Lib", "site-packages")
site.addsitedir(venv_sp)

# pywin32 needs its DLL directory explicitly
pywin32_dll = os.path.join(venv_sp, "pywin32_system32")
if os.path.isdir(pywin32_dll):
    os.add_dll_directory(pywin32_dll)

# Replace argv[0] so main.py's shim sees correct arg positions
sys.argv[0] = os.path.join(ROOT, "main.py")

# Execute main.py
with open(os.path.join(ROOT, "main.py"), "rb") as f:
    source = f.read()
code = compile(source, os.path.join(ROOT, "main.py"), "exec")
sys.path.insert(0, ROOT)
exec(code, {"__name__": "__main__"})
