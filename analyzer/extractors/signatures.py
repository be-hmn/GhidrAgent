"""함수 서명(파라미터, 반환 타입) 추출 - Pyhidra 최적화 버전"""

import logging
from typing import List, Dict, Optional

logger = logging.getLogger(__name__)


def extract_signature(func) -> Dict:
    """함수 서명(파라미터, 반환 타입) 추출
    
    Pyhidra 환경에 최적화:
    - func.getParameters() 직접 사용 (getSignature() 우회)
    - func.getReturnType() 직접 사용
    - FunctionDefinitionDataType 프록시 에러 처리
    
    Returns:
        dict: {
            "parameters": List[Dict],
            "return_type": str
        }
    """
    parameters = []
    return_type = "unknown"

    # 방법 1: func.getParameters() 직접 접근 (Pyhidra 권장)
    try:
        params = func.getParameters()

        for param in params:
            try:
                param_info = {
                    "name": param.getName() or f"arg_{param.getOrdinal()}",
                    "type": str(param.getDataType()),
                    "ordinal": param.getOrdinal(),
                    "storage": str(param.getStorage())
                    if hasattr(param, 'getStorage') else None,
                }
                parameters.append(param_info)
                logger.debug(f"Extracted parameter: {param_info['name']} ({param_info['type']})")

            except Exception as e:
                logger.debug(f"Failed to extract parameter details: {e}")
                continue

    except AttributeError as e:
        logger.debug(f"func.getParameters() not available: {e}")

        # 폴백: getSignature() 시도 (레거시)
        try:
            sig = func.getSignature()

            # getSignature()가 반환되었으면 파라미터 추출 시도
            if hasattr(sig, 'getParameters'):
                for param in sig.getParameters():
                    try:
                        param_info = {
                            "name": param.getName() or f"arg_{param.getOrdinal()}",
                            "type": str(param.getDataType()),
                            "ordinal": param.getOrdinal(),
                            "storage": str(param.getStorage())
                            if hasattr(param, 'getStorage') else None,
                        }
                        parameters.append(param_info)
                    except Exception as e:
                        logger.debug(f"Failed in signature fallback: {e}")
                        continue

        except Exception as fallback_error:
            logger.debug(f"getSignature() fallback also failed: {fallback_error}")

    except Exception as e:
        logger.warning(f"Unexpected error in parameter extraction: {e}")

    # 반환 타입 추출
    return_type = extract_return_type(func)

    return {
        "parameters": parameters,
        "return_type": return_type,
    }


def extract_return_type(func) -> str:
    """반환 타입 추출 (Pyhidra 최적화)
    
    1. func.getReturnType() 직접 사용
    2. 실패 시 함수 본문 분석
    3. 미상 시 "unknown" 반환
    """
    try:
        # 방법 1: 직접 반환 타입 조회
        return_type_obj = func.getReturnType()
        return_type_str = str(return_type_obj).strip()

        # 타입 정규화
        normalized = normalize_type(return_type_str)

        logger.debug(f"Return type: {return_type_str} -> {normalized}")

        return normalized

    except AttributeError as e:
        logger.debug(f"func.getReturnType() not available: {e}")

    except Exception as e:
        logger.debug(f"Failed to get return type: {e}")

    # 폴백: 함수 본문 분석
    try:
        return infer_return_type_from_function_body(func)
    except Exception as e:
        logger.debug(f"Return type inference failed: {e}")
        return "unknown"


def infer_return_type_from_function_body(func) -> str:
    """함수 본문 분석으로 반환 타입 추론
    
    x86/x64 calling convention:
    - 반환값은 보통 EAX/RAX에 저장
    - void 함수는 특별한 반환값 세팅 없음
    """
    try:
        program = func.getProgram()
        listing = program.getListing()
        body = func.getBody()

        if body.getNumAddresses() == 0:
            return "void"

        last_addr = body.getMaxAddress()

        # 마지막 instruction 찾기 (최대 5개 역방향 탐색)
        current_addr = last_addr
        for _ in range(5):
            try:
                instr = listing.getInstructionAt(current_addr)

                if not instr:
                    current_addr = current_addr.subtract(1)
                    continue

                mnemonic = instr.getMnemonicString().lower()

                # RET 명령어 확인
                if "ret" in mnemonic:
                    # 이전 instruction에서 값 설정 여부 확인
                    prev_addr = current_addr.subtract(1)
                    prev_instr = listing.getInstructionAt(prev_addr)

                    if prev_instr:
                        prev_mnemonic = prev_instr.getMnemonicString().lower()

                        # MOV eax/rax 패턴 감지
                        if "mov" in prev_mnemonic and ("eax" in prev_mnemonic or "rax" in prev_mnemonic):
                            return "int"

                        # XOR eax, eax (반환 0)
                        if "xor" in prev_mnemonic and ("eax" in prev_mnemonic or "rax" in prev_mnemonic):
                            return "int"

                    return "int"  # 기본값

                current_addr = current_addr.subtract(1)

            except Exception:
                current_addr = current_addr.subtract(1)
                continue

        return "void"

    except Exception as e:
        logger.debug(f"Failed to infer return type from body: {e}")
        return "unknown"


def normalize_type(type_str: str) -> str:
    """Ghidra 타입을 표준 타입으로 정규화
    
    Args:
        type_str: Ghidra가 반환한 타입 문자열
    
    Returns:
        표준화된 타입 이름
    """
    type_lower = str(type_str).lower().strip()

    # 공통 타입 매핑
    type_mapping = {
        "void": "void",
        "undefined": "int",
        "undefined4": "int",
        "undefined8": "long",
        "int": "int",
        "long": "long",
        "short": "short",
        "char": "char",
        "byte": "char",
        "float": "float",
        "double": "double",
        "pointer": "void*",
        "uint": "uint",
        "ulong": "ulong",
        "bool": "bool",
    }

    # 정확한 매칭
    for key, normalized in type_mapping.items():
        if key == type_lower:
            return normalized

    # 부분 매칭 (타입이 포함된 경우)
    for key, normalized in type_mapping.items():
        if key in type_lower:
            return normalized

    # 반환 타입이 포인터인 경우
    if "*" in type_lower:
        return "pointer"

    return type_str  # 정규화 불가능하면 원본 반환