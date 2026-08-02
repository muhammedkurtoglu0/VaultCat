"""Structured logging via loguru — file + stderr with rotation and retention.

Usage::

    from core.logger import logger
    logger.info("Scan started")
    logger.warning("TLS verify disabled")
    logger.error("Request failed", exc_info=True)
"""

from __future__ import annotations

import sys
from pathlib import Path

try:
    from loguru import logger as _logger
except ImportError:
    # Graceful fallback — loguru may not be installed yet during first setup.
    # When the user runs ``uv sync`` or ``pip install -r requirements.txt``
    # it will be picked up on the next import.
    import logging as _logging

    _fallback = _logging.getLogger("vault-pentest")
    _fallback.setLevel(_logging.DEBUG)
    _h = _logging.StreamHandler(sys.stderr)
    _h.setFormatter(_logging.Formatter("%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"))
    _fallback.addHandler(_h)

    # Minimal duck-type so ``logger.info(...)`` works with the stdlib fallback.
    class _LoggerProxy:
        def __getattr__(self, name: str):
            return getattr(_fallback, name)
        def opt(self, *_args: object, **_kwargs: object) -> "_LoggerProxy":
            return self

    logger: _LoggerProxy = _LoggerProxy()  # type: ignore[no-redef]
else:
    _logger.remove()  # drop default handler

    # ── Custom SUCCESS level (25, between INFO=20 and WARNING=30) ──────
    _logger.level("SUCCESS", no=25, color="<green>", icon="✅")

    LOG_DIR = Path(__file__).resolve().parent.parent / "logs"
    LOG_DIR.mkdir(exist_ok=True)

    _logger.add(
        LOG_DIR / "vault-pentest-{time:YYYY-MM-DD}.log",
        rotation="10 MB",
        retention="30 days",
        compression="gz",
        level="DEBUG",
        format=(
            "{time:YYYY-MM-DD HH:mm:ss.SSS} | {level: <8} | "
            "{name}:{function}:{line} | {message}"
        ),
        backtrace=True,
        diagnose=True,
    )

    _logger.add(
        sys.stderr,
        level="INFO",
        format="<level>{level: <8}</level> | <level>{message}</level>",
        colorize=True,
    )

    logger = _logger
