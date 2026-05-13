import logging
from typing import Dict, List

logger = logging.getLogger(__name__)


def extract_api_calls(flat_api, func) -> Dict[str, int]:
    """API 호출 추출 - 호출 횟수 포함 (개선 버전)

    Returns:
        dict: {
            "api_name": count,
            ...
        }
    """
    program = flat_api.getCurrentProgram()
    listing = program.getListing()
    ref_mgr = program.getReferenceManager()
    symbol_table = program.getSymbolTable()

    api_calls = {}  # {api_name: count}

    try:
        instructions = listing.getInstructions(
            func.getBody(),
            True,
        )

        while instructions.hasNext():
            try:
                instruction = instructions.next()
                refs = ref_mgr.getReferencesFrom(
                    instruction.getAddress()
                )

                for ref in refs:
                    try:
                        if ref.isExternalReference():
                            # 외부 참조 (API 호출)
                            symbol = symbol_table.getPrimarySymbol(
                                ref.getToAddress()
                            )

                            api_name = None
                            if symbol:
                                api_name = symbol.getName()
                            else:
                                api_name = str(ref.getToAddress())

                            # 호출 횟수 증가
                            api_calls[api_name] = api_calls.get(api_name, 0) + 1

                    except Exception as e:
                        logger.debug(f"Failed to process reference: {e}")
                        continue

            except Exception as e:
                logger.debug(f"Failed to process instruction: {e}")
                continue

    except Exception as e:
        logger.warning(f"Failed to extract API calls: {e}")

    return api_calls


def extract_api_calls_legacy(flat_api, func) -> List[str]:
    """기존 호환성을 위한 래퍼 (정렬된 API명 리스트)"""
    api_calls_dict = extract_api_calls(flat_api, func)
    return sorted(api_calls_dict.keys())