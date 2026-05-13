import logging
from typing import Dict, List

logger = logging.getLogger(__name__)


def extract_callgraph(flat_api, func) -> Dict:
    """호출 그래프 추출 (기존 코드 유지)

    Returns:
        dict: {
            "calls": List[str],
            "called_by": List[str]
        }
    """
    calls = []
    called_by = []

    try:
        for f in func.getCalledFunctions(flat_api.monitor):
            try:
                calls.append(f.getName())
            except Exception as e:
                logger.debug(f"Failed to get called function name: {e}")
                continue

    except Exception as e:
        logger.warning(f"Failed to get called functions: {e}")

    try:
        for f in func.getCallingFunctions(flat_api.monitor):
            try:
                called_by.append(f.getName())
            except Exception as e:
                logger.debug(f"Failed to get calling function name: {e}")
                continue

    except Exception as e:
        logger.warning(f"Failed to get calling functions: {e}")

    return {
        "calls": sorted(set(calls)),
        "called_by": sorted(set(called_by)),
    }