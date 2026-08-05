"""One-shot migration: replace print() with logger.* across the project.

Patterns:
  print("[+] ...")          → logger.success(...)
  print("[!] ...")          → logger.error(...)
  print("[-] ...")          → logger.warning(...)
  print("[*] ...")          → logger.info(...)
  print("[PASS] ...")       → logger.info(...)
  print("\n...")            → logger.info(...)
  print("==="...)           → logger.info(...)
  print(f"...")             → logger.info(...)
  generic print(...)        → logger.debug(...)

Skips: cli.py, chat_ui.py, llm_engine.py (user-facing terminal output)
"""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

SKIP_FILES = {
    "cli.py",
    "chat_ui.py",
    "gui_app.py",
    "migrate_to_logger.py",
}

SKIP_DIRS = {
    ".venv", "Lib", "__pycache__", ".git",
    "vaultcat-lab", "vault_pentest_tool.egg-info",
}

# Files that already have the logger import (don't re-add)
_HAS_LOGGER_IMPORT: set[str] = set()
for py_file in ROOT.rglob("*.py"):
    if any(d in py_file.parts for d in SKIP_DIRS):
        continue
    try:
        content = py_file.read_text(encoding="utf-8")
        if "from core.logger import logger" in content or "from core.logger import" in content:
            _HAS_LOGGER_IMPORT.add(str(py_file))
    except Exception:
        pass


def classify_print(line: str) -> tuple[str, str]:
    """Return (logger_level, cleaned_content) for a print() call."""
    # Extract the content inside print()
    m = re.search(r'print\((.*)\)\s*$', line)
    if not m:
        return "debug", line

    inner = m.group(1).strip()

    # Multi-line print detection (fragile, skip)
    if inner.count("(") != inner.count(")") + inner.count('"') % 2:
        return "skip", line

    # Classify by prefix pattern
    inner_lower = inner.lower()

    if inner.startswith(('f"[!]', '"[-]', "'[-]", 'f"[-]', "f'[-]")):
        return "error", inner
    elif inner.startswith(('f"[+]', '"[+]', "'[+]", 'f"[PASS]', '"[PASS]')):
        return "success", inner
    elif inner.startswith(('f"[-]', "'[-]", "f'[-]")):
        return "warning", inner
    elif inner.startswith(('f"[*]', '"[*]', "'[*]", "f'[*]")):
        return "info", inner
    elif inner.startswith(('f"\\n', '"\\n', "'\\n", 'f"=', 'f"  ', '"=', '"  ')):
        return "info", inner
    elif "error" in inner_lower or "fail" in inner_lower or "exception" in inner_lower:
        return "error", inner
    elif "warning" in inner_lower or "warn" in inner_lower:
        return "warning", inner
    else:
        return "info", inner


def process_file(filepath: Path) -> bool:
    """Rewrite a single file. Returns True if changed."""
    try:
        lines = filepath.read_text(encoding="utf-8").splitlines(True)
    except Exception:
        return False

    changed = False
    new_lines = []
    has_any_print = any("print(" in line and not line.strip().startswith("#") for line in lines)

    if not has_any_print:
        return False

    for i, line in enumerate(lines):
        stripped = line.strip()

        # Skip comments and non-print lines
        if not stripped.startswith("print("):
            new_lines.append(line)
            continue

        # Skip if it's inside a string or comment
        if line.lstrip() != line and "#" in line.split("print(")[0]:
            new_lines.append(line)
            continue

        level, inner = classify_print(stripped)
        if level == "skip":
            new_lines.append(line)
            continue

        # Determine indentation
        indent = line[:len(line) - len(line.lstrip())]

        # Build replacement
        if level == "success":
            replacement = f"{indent}logger.success({inner})\n"
        elif level == "error":
            replacement = f"{indent}logger.error({inner})\n"
        elif level == "warning":
            replacement = f"{indent}logger.warning({inner})\n"
        elif level == "info":
            replacement = f"{indent}logger.info({inner})\n"
        else:
            replacement = f"{indent}logger.debug({inner})\n"

        new_lines.append(replacement)
        changed = True

    if not changed:
        return False

    # Add logger import if needed
    filepath_str = str(filepath.resolve())
    if filepath_str not in _HAS_LOGGER_IMPORT and "from core.logger import logger" not in "".join(new_lines):
        # Find the right place to insert (after last import, before first code)
        insert_idx = 0
        for i, line in enumerate(new_lines):
            if line.startswith("import ") or line.startswith("from "):
                insert_idx = i + 1
            elif line.strip() == "" and insert_idx > 0:
                continue
            elif insert_idx > 0:
                break

        # Insert after docstring if present
        if insert_idx == 0:
            for i, line in enumerate(new_lines):
                if '"""' in line or "'''" in line:
                    insert_idx = i + 1
                elif line.strip() and not line.startswith("#"):
                    insert_idx = i
                    break

        new_lines.insert(insert_idx, "from core.logger import logger\n")
        if insert_idx > 0 and not new_lines[insert_idx - 1].strip():
            pass  # already a blank line before
        else:
            new_lines.insert(insert_idx, "\n")

    filepath.write_text("".join(new_lines), encoding="utf-8")
    return True


def main():
    files_processed = 0
    prints_replaced = 0

    for py_file in sorted(ROOT.rglob("*.py")):
        # Skip excluded dirs
        if any(d in py_file.parts for d in SKIP_DIRS):
            continue
        if py_file.name in SKIP_FILES:
            continue
        # Skip tests (they use print for debugging)
        if "tests" in py_file.parts:
            continue

        # Count prints before
        try:
            before_content = py_file.read_text(encoding="utf-8")
        except Exception:
            continue
        before_count = before_content.count("print(")

        if before_count == 0:
            continue

        if process_file(py_file):
            after_count = py_file.read_text(encoding="utf-8").count("print(")
            replaced = before_count - after_count
            prints_replaced += replaced
            files_processed += 1
            rel = py_file.relative_to(ROOT)
            print(f"  {rel}: {replaced} print() → logger")

    print(f"\nDone: {files_processed} files, {prints_replaced} print() calls replaced.")


if __name__ == "__main__":
    main()
