"""함수 데이터 통합 추출 - Pyhidra 최적화"""

import logging
from typing import Dict, Optional, List

from analyzer.extractors.callgraph import extract_callgraph
from analyzer.extractors.api_calls import extract_api_calls, extract_api_calls_split
from analyzer.extractors.strings import (
    extract_resolved_data_from_decompile,
    extract_strings,
)
from analyzer.extractors.signatures import extract_signature
from analyzer.extractors.metrics import extract_metrics
from analyzer.extractors.call_sequence import extract_call_sequence
from analyzer.extractors.decompiler import extract_decompiled_code
from analyzer.extractors.validation import extract_validation_constraints

logger = logging.getLogger(__name__)


def should_analyze_function(func) -> bool:
    """함수를 분석해야 하는지 판단 (노이즈 감소)

    다음 함수는 건너뜀:
    - Thunk 함수
    - CRT 런타임 함수 (leading underscore)
    - Unwind 함수

    Args:
        func: Ghidra Function 객체

    Returns:
        True if should analyze, False if skip
    """
    func_name = func.getName().lower()

    # 1. Thunk 함수 제외
    try:
        if func.isThunk():
            logger.debug(f"Skipping thunk function: {func.getName()}")
            return False
    except Exception:
        pass  # isThunk() 미지원 환경

    # 2. CRT 런타임 함수 제외 (leading underscore로 시작하는 많은 CRT 함수들)
    # 예: _CRT_INIT, _mainCRTStartup, __cxa_finalize 등
    if func.getName().startswith("_"):
        # 예외: _main, entry 등은 분석
        if func.getName() in ["_main", "_start", "entry", "_entry"]:
            pass  # 이 경우는 분석
        else:
            logger.debug(f"Skipping CRT function: {func.getName()}")
            return False

    # 3. Unwind 함수 제외 (예외 처리 관련)
    if "unwind" in func_name:
        logger.debug(f"Skipping unwind function: {func.getName()}")
        return False

    return True


def extract_function_data(flat_api, func, decompiler=None) -> Optional[Dict]:
    """함수 데이터 통합 추출 (Pyhidra 최적화)

    이 함수는 다음 정보를 수집합니다:
    - 함수 이름, 크기
    - 호출 관계 (calls, called_by)
    - 파라미터 및 반환 타입
    - API 호출
    - 참조 문자열
    - 복잡도 메트릭
    - 호출 순서
    """

    func_name = func.getName()
    logger.debug(f"Extracting data for {func_name}")

    # 함수 필터링 (노이즈 감소)
    if not should_analyze_function(func):
        return None  # 건너뜀

    try:
        # 1. 호출 그래프
        callgraph = extract_callgraph(flat_api, func)

        # 2. 파라미터 및 반환 타입 (Pyhidra 최적화)
        signature = extract_signature(func)

        # 3. API 호출
        api_calls_split = extract_api_calls_split(flat_api, func)
        api_calls_dict = api_calls_split.get("standard", {})
        custom_calls_dict = api_calls_split.get("custom", {})

        # 4. Decompile code
        decompiled_code = extract_decompiled_code(decompiler, func)

        # 5. 문자열 (노이즈 제거 포함)
        strings_list = extract_strings(flat_api, func)
        resolved_data = extract_resolved_data_from_decompile(
            flat_api,
            decompiled_code,
        )
        validation_constraints = extract_validation_constraints(
            decompiled_code,
            resolved_data,
        )

        # 6. 메트릭
        metrics = extract_metrics(flat_api, func)

        # 7. 기본 정보
        body_size = func.getBody().getNumAddresses()

        # 8. 호출 순서
        call_sequence = extract_call_sequence(flat_api, func)

        # 9. MCP 최적화 반환 구조
        return {
            # 기본 정보 (하위 호환성)
            "name": func_name,
            "body_size": body_size,
            "calls": callgraph.get("calls", []),
            "called_by": callgraph.get("called_by", []),
            "api_calls": list(api_calls_dict.keys()),
            "custom_calls": list(custom_calls_dict.keys()),
            "strings": _merge_string_values(strings_list, resolved_data),
            "parameters": signature["parameters"],
            "return_type": signature["return_type"],

            # 확장 정보
            "metrics": metrics,
            "call_sequence": call_sequence,
            "decompiled_code": decompiled_code,
            "resolved_data": resolved_data,
            "validation_constraints": validation_constraints,
        }

    except Exception as e:
        logger.exception(f"Failed to extract function data for {func_name}: {e}")

        # 폴백: 최소 정보만 반환
        return {
            "name": func_name,
            "body_size": func.getBody().getNumAddresses(),
            "calls": [],
            "called_by": [],
            "api_calls": [],
            "custom_calls": [],
            "strings": [],
            "parameters": [],
            "return_type": "unknown",
            "metrics": {},
            "call_sequence": [],
            "decompiled_code": None,
            "resolved_data": [],
            "validation_constraints": [],
            "error": str(e),
        }


def _safe_string_values(strings_list: List[Dict]) -> List[str]:
    """문자열 리스트에서 value만 안전하게 추출합니다."""
    if not isinstance(strings_list, list):
        return []

    values: List[str] = []
    for item in strings_list:
        if isinstance(item, dict):
            value = item.get("value")
            if value:
                values.append(value)
    return values


def _merge_string_values(
        strings_list: List[Dict],
        resolved_data: List[Dict],
) -> List[str]:
    """Merge normal string references with DAT_xxx resolved values."""
    values: List[str] = []
    seen = set()

    for value in _safe_string_values(strings_list):
        if value in seen:
            continue
        seen.add(value)
        values.append(value)

    for item in resolved_data:
        if not isinstance(item, dict):
            continue
        value = item.get("value")
        if not value or value in seen:
            continue
        seen.add(value)
        values.append(value)

    return values
