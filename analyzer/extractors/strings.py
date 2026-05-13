"""문자열 추출 - 노이즈 제거 필터링 적용"""

import logging
import re
from typing import List, Dict, Optional

logger = logging.getLogger(__name__)


def extract_strings(flat_api, func) -> List[Dict]:
    """문자열 추출 - 값과 주소 포함 (개선 버전)
    
    노이즈 제거:
    - 길이 4 미만 제거
    - 0x/0X prefix 제거
    - Pure hex 제거
    - alphabetic character 없는 문자열 제거

    Returns:
        list: [
            {
                "value": "string content",
                "address": "0x12345",
                "length": 13,
                "type": "string"
            },
            ...
        ]
    """
    program = flat_api.getCurrentProgram()
    listing = program.getListing()
    ref_mgr = program.getReferenceManager()
    memory = program.getMemory()

    results = []
    seen_values = set()  # 중복 제거 (값 기준)

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
                        target_addr = ref.getToAddress()
                        data = listing.getDefinedDataAt(target_addr)

                        if not data:
                            continue

                        # 데이터 타입 확인
                        data_type = str(data.getDataType())

                        # 문자열 타입 필터링
                        if not is_string_type(data_type):
                            continue

                        # 메모리에서 실제 문자열 추출
                        string_value = extract_string_value(
                            memory,
                            target_addr,
                        )

                        if not string_value:
                            continue

                        # 노이즈 필터링
                        if not is_valid_string(string_value):
                            logger.debug(f"Filtered noise string: {string_value}")
                            continue

                        # 중복 제거 (값 기준)
                        if string_value in seen_values:
                            continue

                        seen_values.add(string_value)

                        results.append({
                            "value": string_value,
                            "address": str(target_addr),
                            "length": len(string_value),
                            "type": data_type,
                        })

                        logger.debug(f"Extracted string: {string_value}")

                    except Exception as e:
                        logger.debug(f"Failed to process string reference: {e}")
                        continue

            except Exception as e:
                logger.debug(f"Failed to process instruction: {e}")
                continue

    except Exception as e:
        logger.warning(f"Failed to extract strings: {e}")

    return results


def extract_strings_legacy(flat_api, func) -> List[str]:
    """기존 호환성을 위한 래퍼 (문자열 값 리스트만)"""
    strings_list = extract_strings(flat_api, func)
    return sorted(set([s["value"] for s in strings_list]))


def extract_string_value(memory, address) -> Optional[str]:
    """메모리에서 null-terminated 문자열 추출

    Args:
        memory: Ghidra Memory 객체
        address: 문자열 시작 주소

    Returns:
        추출된 문자열 또는 None
    """
    try:
        bytes_list = []

        # 최대 1024바이트까지 읽기 (너무 큰 버퍼 방지)
        for i in range(1024):
            try:
                byte = memory.getByte(address.add(i)) & 0xFF

                # Null-terminator 만나면 중단
                if byte == 0:
                    break

                # 출력 가능한 ASCII 범위 (일부 확장 ASCII 포함)
                if byte < 9 or (byte > 13 and byte < 32) or byte > 126:
                    # 비출력 문자는 스킵하되, 널이 아니면 스트링 계속
                    if byte not in (9, 10, 13):  # tab, newline, carriage return 제외
                        break

                bytes_list.append(byte)

            except Exception:
                break

        if not bytes_list:
            return None

        # UTF-8 또는 ASCII로 디코딩
        try:
            return bytes(bytes_list).decode('utf-8', errors='ignore')
        except Exception:
            return bytes(bytes_list).decode('latin-1', errors='ignore')

    except Exception as e:
        logger.debug(f"Failed to extract string value: {e}")
        return None


def is_string_type(data_type: str) -> bool:
    """데이터 타입이 문자열 관련인지 확인"""
    data_type_lower = str(data_type).lower()

    string_indicators = [
        "string",
        "char",
        "wchar",
        "utf",
        "ascii",
    ]

    return any(indicator in data_type_lower for indicator in string_indicators)


def is_valid_string(value: str) -> bool:
    """문자열이 유효한지 필터링 (노이즈 제거)
    
    필터 기준:
    1. 최소 길이 4 이상
    2. 0x/0X prefix 제거
    3. Pure hex 제거 (모두 16진수)
    4. alphabetic character 포함 필수
    5. 공백만 있는 문자열 제거
    
    Args:
        value: 검증할 문자열
    
    Returns:
        True if valid, False if noise
    """
    if not value:
        return False

    # 1. 최소 길이 필터
    if len(value) < 4:
        return False

    # 2. 0x prefix 필터
    if value.startswith(("0x", "0X")):
        return False

    # 3. 공백만 있는 경우
    if value.strip() == "":
        return False

    # 4. Alphabetic character 포함 여부 (메인 필터)
    if not any(c.isalpha() for c in value):
        return False

    # 5. Pure hex 필터 (모든 문자가 0-9, a-f, A-F인 경우)
    if is_pure_hex(value):
        return False

    # 6. Common noise patterns
    if is_noise_pattern(value):
        return False

    return True


def is_pure_hex(value: str) -> bool:
    """문자열이 순수 16진수인지 확인
    
    Args:
        value: 검증할 문자열
    
    Returns:
        True if pure hex, False otherwise
    """
    # 빈 문자열 제외
    if not value:
        return False

    # 모든 문자가 16진수 범위인지 확인
    return all(c in "0123456789abcdefABCDEF" for c in value)


def is_noise_pattern(value: str) -> bool:
    """알려진 노이즈 패턴 감지
    
    Examples:
    - "004052f8" (메모리 주소)
    - "-0x1" (음수 상수)
    - "0xf0" (상수)
    - 반복되는 패턴 ("aaaa", "1111")
    """

    # 음수 상수 패턴
    if value.startswith("-0x"):
        return True

    # 메모리 주소 같은 패턴 (8개 이상의 hex)
    if len(value) >= 8 and is_pure_hex(value):
        return True

    # 단순 반복 패턴 (예: "aaaa", "1111")
    if len(set(value)) == 1:
        return True

    # 단순 2문자 반복 (예: "aaaa", "abab")
    if len(value) >= 4:
        pattern = value[:2]
        if pattern * (len(value) // 2) == value[:len(pattern) * (len(value) // 2)]:
            return is_pure_hex(pattern) or not any(c.isalpha() for c in pattern)

    return False