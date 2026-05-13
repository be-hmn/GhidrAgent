import logging
from typing import Dict

logger = logging.getLogger(__name__)


def extract_xrefs(flat_api, func) -> Dict:
    """Cross-Reference 추출 - 상세 분류 (개선 버전)

    Returns:
        dict: {
            "internal_calls": int,
            "external_references": int,
            "data_references": int,
            "flow_references": int,
            "fallthrough": int
        }
    """
    program = flat_api.getCurrentProgram()
    ref_mgr = program.getReferenceManager()

    xrefs = {
        "internal_calls": 0,
        "external_references": 0,
        "data_references": 0,
        "flow_references": 0,
        "fallthrough": 0,
    }

    try:
        for addr in func.getBody():
            try:
                # 이 주소에서 나가는 참조들
                refs_from = list(ref_mgr.getReferencesFrom(addr))

                for ref in refs_from:
                    try:
                        ref_type = str(ref.getReferenceType())

                        if ref.isExternalReference():
                            # 외부 참조 (API 호출)
                            xrefs["external_references"] += 1

                        elif "CALL" in ref_type:
                            # 함수 호출
                            xrefs["internal_calls"] += 1

                        elif "DATA" in ref_type or "READ" in ref_type or "WRITE" in ref_type:
                            # 데이터 참조
                            xrefs["data_references"] += 1

                        elif "JUMP" in ref_type or "BRANCH" in ref_type:
                            # 점프/분기
                            xrefs["flow_references"] += 1

                        elif "FALL" in ref_type:
                            # Fall-through
                            xrefs["fallthrough"] += 1

                    except Exception as e:
                        logger.debug(f"Failed to classify reference: {e}")
                        continue

            except Exception as e:
                logger.debug(f"Failed to process address: {e}")
                continue

    except Exception as e:
        logger.warning(f"Failed to extract xrefs: {e}")

    return xrefs


def extract_xrefs_legacy(flat_api, func) -> Dict[str, int]:
    """기존 호환성을 위한 래퍼"""
    xrefs_detailed = extract_xrefs(flat_api, func)

    return {
        "xrefs_in": xrefs_detailed["internal_calls"] + xrefs_detailed["external_references"],
        "xrefs_out": xrefs_detailed["flow_references"] + xrefs_detailed["fallthrough"],
    }