"""함수 데이터 통합 추출 - Pyhidra 최적화"""

import logging
from typing import Dict

from analyzer.extractors.callgraph import extract_callgraph
from analyzer.extractors.api_calls import extract_api_calls
from analyzer.extractors.strings import extract_strings
from analyzer.extractors.signatures import extract_signature
from analyzer.extractors.metrics import extract_metrics
from analyzer.extractors.call_sequence import extract_call_sequence

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


def extract_function_data(flat_api, func) -> Dict:
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
        api_calls_dict = extract_api_calls(flat_api, func)

        # 4. 문자열 (노이즈 제거 포함)
        strings_list = extract_strings(flat_api, func)

        # 5. 메트릭
        metrics = extract_metrics(flat_api, func)

        # 6. 기본 정보
        body_size = func.getBody().getNumAddresses()

        # 7. 호출 순서
        call_sequence = extract_call_sequence(flat_api, func)

        # 8. MCP 최적화 반환 구조
        return {
            # 기본 정보 (하위 호환성)
            "name": func_name,
            "body_size": body_size,
            "calls": callgraph["calls"],
            "called_by": callgraph["called_by"],
            "api_calls": list(api_calls_dict.keys()),
            "strings": [s["value"] for s in strings_list],
            "parameters": signature["parameters"],
            "return_type": signature["return_type"],

            # 확장 정보
            "metrics": metrics,
            "call_sequence": call_sequence,
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
            "strings": [],
            "parameters": [],
            "return_type": "unknown",
            "metrics": {},
            "call_sequence": [],
            "error": str(e),
        }