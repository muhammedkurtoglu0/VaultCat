param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]] $CliArgs
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$python = Join-Path $env:USERPROFILE ".cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe"
$deps = Join-Path $repoRoot ".codex_deps"
$pywin32System32 = Join-Path $deps "pywin32_system32"
$pywin32Win32 = Join-Path $deps "win32"
$pywin32Lib = Join-Path $pywin32Win32 "lib"
$pythonwin = Join-Path $deps "pythonwin"

if (-not (Test-Path -LiteralPath $python)) {
    throw "Bundled Codex Python not found: $python"
}

if (-not (Test-Path -LiteralPath $deps)) {
    throw "Dependency target not found: $deps. Install with: & '$python' -m pip install -r requirements.txt --target .codex_deps"
}

$env:PYTHONPATH = "$pywin32Win32;$pywin32Lib;$pythonwin;$deps;$repoRoot"
$env:PATH = "$pywin32System32;$env:PATH"
$env:PYTHONUTF8 = "1"
$env:PYTHONIOENCODING = "utf-8"
& $python (Join-Path $repoRoot "main.py") @CliArgs
