"""Decompiler output extraction."""

import logging
from typing import Optional

logger = logging.getLogger(__name__)


def create_decompiler(program):
    """Create and initialize a Ghidra decompiler for the given program."""
    from ghidra.app.decompiler import DecompInterface

    decompiler = DecompInterface()
    if not decompiler.openProgram(program):
        logger.warning("Failed to open program in decompiler")
    return decompiler


def dispose_decompiler(decompiler) -> None:
    """Release decompiler resources."""
    if decompiler is None:
        return

    try:
        decompiler.dispose()
    except Exception as exc:
        logger.debug("Failed to dispose decompiler: %s", exc)


def extract_decompiled_code(
        decompiler,
        func,
        timeout_sec: int = 30,
) -> Optional[str]:
    """Extract C-like decompiled code for a function."""
    if decompiler is None:
        return None

    try:
        from ghidra.util.task import ConsoleTaskMonitor

        result = decompiler.decompileFunction(
            func,
            timeout_sec,
            ConsoleTaskMonitor(),
        )

        if result is None:
            return None

        if not result.decompileCompleted():
            logger.debug(
                "Decompiler failed for %s: %s",
                func.getName(),
                result.getErrorMessage(),
            )
            return None

        decompiled_function = result.getDecompiledFunction()
        if decompiled_function is None:
            return None

        return decompiled_function.getC()

    except Exception as exc:
        logger.debug("Failed to decompile %s: %s", func.getName(), exc)
        return None
