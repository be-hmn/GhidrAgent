"""함수 내 호출 순서 추출"""

import logging
from typing import Dict, List

logger = logging.getLogger(__name__)


def extract_call_sequence(flat_api, func) -> List[Dict]:
    """함수 내 CALL 명령어의 호출 순서를 추출합니다.

    Returns:
        list: [{"index": 0, "target": "MessageBoxA", "description": "메시지박스 표시"}, ...]
    """
    program = flat_api.getCurrentProgram()
    listing = program.getListing()
    ref_mgr = program.getReferenceManager()
    symbol_table = program.getSymbolTable()

    call_sequence: List[Dict] = []
    call_index = 0

    try:
        instructions = listing.getInstructions(func.getBody(), True)

        while instructions.hasNext():
            instr = instructions.next()
            mnemonic = instr.getMnemonicString().lower()

            if "call" not in mnemonic:
                continue

            call_info = _build_call_info(ref_mgr, symbol_table, instr.getAddress())
            if not call_info:
                continue

            call_info["index"] = call_index
            call_info["description"] = _describe_target(call_info["target"])
            call_sequence.append(call_info)
            call_index += 1

    except Exception as exc:
        logger.warning("Call sequence extraction failed: %s", exc)

    return call_sequence


def _build_call_info(ref_mgr, symbol_table, address) -> Dict | None:
    """CALL 대상 심볼을 해석합니다."""
    try:
        refs = ref_mgr.getReferencesFrom(address)
        for ref in refs:
            target_addr = ref.getToAddress()
            symbol = symbol_table.getPrimarySymbol(target_addr)
            target_name = symbol.getName() if symbol else str(target_addr)
            return {
                "target": target_name,
                "is_external": ref.isExternalReference(),
            }
    except Exception:
        return None

    return None


def _describe_target(target_name: str) -> str:
    """호출 대상 이름에서 간단한 설명을 생성합니다."""
    target_lower = target_name.lower()

    if any(token in target_lower for token in ["scanf", "read", "get"]):
        return "입력 받기"
    if any(token in target_lower for token in ["printf", "write", "puts", "put"]):
        return "출력 하기"
    if "strncmp" in target_lower:
        return "문자열 비교 (길이 제한)"
    if any(token in target_lower for token in ["strcmp", "strcpy", "strlen", "strstr"]):
        return "문자열 처리"
    if any(token in target_lower for token in ["malloc", "alloc", "new"]):
        return "메모리 할당"
    if any(token in target_lower for token in ["free", "delete"]):
        return "메모리 해제"
    if any(token in target_lower for token in ["memcpy", "memset", "memmove"]):
        return "메모리 조작"
    if "dialogbox" in target_lower:
        return "다이얼로그 표시"
    if "messagebox" in target_lower:
        return "메시지박스 표시"
    if "getdlgitemtext" in target_lower:
        return "다이얼로그 항목 텍스트 읽기"
    if "setdlgitemtext" in target_lower:
        return "다이얼로그 항목 텍스트 설정"
    if "enddialog" in target_lower:
        return "다이얼로그 종료"
    if any(token in target_lower for token in ["exit", "abort", "terminate"]):
        return "프로그램 종료"
    if "system" in target_lower:
        return "시스템 명령 실행"
    if target_lower.startswith("fun_"):
        return "내부 함수 호출"

    return "함수 호출"

