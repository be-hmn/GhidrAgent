import logging
from typing import Dict, List

logger = logging.getLogger(__name__)

_STANDARD_LIB_PREFIXES = (
    "printf",
    "scanf",
    "puts",
    "gets",
    "read",
    "write",
    "open",
    "close",
    "malloc",
    "free",
    "calloc",
    "realloc",
    "memcpy",
    "memmove",
    "memset",
    "strcmp",
    "strncmp",
    "strcpy",
    "strncpy",
    "strlen",
    "strstr",
    "atoi",
    "exit",
    "abort",
)

_PE_LIB_PREFIXES = (
    "get",
    "set",
    "create",
    "open",
    "close",
    "read",
    "write",
    "loadlibrary",
    "getprocaddress",
    "messagebox",
    "dialogbox",
    "enddialog",
    "virtualalloc",
    "virtualfree",
    "heapalloc",
    "heapfree",
    "reg",
    "crypt",
    "ws",
    "socket",
)

_STANDARD_LIB_ALLOWED = {
    "__isoc99_scanf",
    "__libc_start_main",
    "__stack_chk_fail",
    "__assert_fail",
}

_PE_LIB_ALLOWED = {
    "exitprocess",
    "getmodulehandlea",
    "getmodulehandlew",
    "getcommandlinea",
    "getcommandlinew",
    "getstartupinfoa",
    "getstartupinfow",
}


def extract_api_calls(flat_api, func) -> Dict[str, int]:
    """표준 라이브러리 호출만 반환합니다."""
    split = extract_api_calls_split(flat_api, func)
    return split["standard"]


def extract_api_calls_split(flat_api, func) -> Dict[str, Dict[str, int]]:
    """표준/사용자 정의 호출을 분리해 반환합니다.

    Returns:
        {
            "standard": {"api_name": count, ...},
            "custom": {"api_name": count, ...},
        }
    """
    program = flat_api.getCurrentProgram()
    listing = program.getListing()
    ref_mgr = program.getReferenceManager()
    symbol_table = program.getSymbolTable()

    exec_format = _get_exec_format(program)
    standard_calls: Dict[str, int] = {}
    custom_calls: Dict[str, int] = {}

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
                        if not _is_api_call(ref, instruction):
                            continue

                        symbol = symbol_table.getPrimarySymbol(
                            ref.getToAddress()
                        )
                        api_name = _resolve_api_name(ref, symbol)

                        if not api_name or not _is_api_name_base(api_name):
                            continue

                        if _is_whitelisted_api(api_name.lower(), exec_format):
                            standard_calls[api_name] = standard_calls.get(api_name, 0) + 1
                        else:
                            custom_calls[api_name] = custom_calls.get(api_name, 0) + 1

                    except Exception as e:
                        logger.debug(f"Failed to process reference: {e}")
                        continue

            except Exception as e:
                logger.debug(f"Failed to process instruction: {e}")
                continue

    except Exception as e:
        logger.warning(f"Failed to extract API calls: {e}")

    return {
        "standard": standard_calls,
        "custom": custom_calls,
    }


def _is_api_call(ref, instruction) -> bool:
    """외부 호출인지 여부를 판별합니다."""
    try:
        if not ref.isExternalReference():
            return False

        ref_type = str(ref.getReferenceType()).upper()
        if "CALL" not in ref_type:
            return False

        mnemonic = instruction.getMnemonicString().lower()
        if "call" not in mnemonic and "bl" not in mnemonic and "jmp" not in mnemonic:
            return False

        return True
    except Exception:
        return False


def _resolve_api_name(ref, symbol) -> str | None:
    """심볼에서 API 이름을 해석하고 정규화합니다."""
    if symbol:
        api_name = symbol.getName()
    else:
        api_name = str(ref.getToAddress())

    return _normalize_api_name(api_name)


def _normalize_api_name(api_name: str) -> str:
    """플랫폼별 접두/접미를 제거합니다."""
    if not api_name:
        return api_name

    normalized = api_name

    if normalized.startswith("PTR_"):
        normalized = normalized[4:]

    if "@plt" in normalized:
        normalized = normalized.replace("@plt", "")

    return normalized


def _is_api_name(api_name: str, exec_format: str) -> bool:
    """내부/래퍼 함수를 제외한 API 이름인지 검사합니다."""
    if not _is_api_name_base(api_name):
        return False

    return _is_whitelisted_api(api_name.lower(), exec_format)


def _is_whitelisted_api(lowered_name: str, exec_format: str) -> bool:
    """실행 포맷별 화이트리스트 확인"""
    if exec_format == "PE":
        if lowered_name in _PE_LIB_ALLOWED:
            return True
        return lowered_name.startswith(_PE_LIB_PREFIXES)

    if lowered_name in _STANDARD_LIB_ALLOWED:
        return True

    return lowered_name.startswith(_STANDARD_LIB_PREFIXES)


def _get_exec_format(program) -> str:
    """실행 포맷(ELF/PE)을 식별합니다."""
    try:
        format_name = str(program.getExecutableFormat()).lower()
    except Exception:
        format_name = ""

    if "portable executable" in format_name or "pe" in format_name:
        return "PE"
    if "elf" in format_name:
        return "ELF"

    return "UNKNOWN"


def _is_api_name_base(api_name: str) -> bool:
    """내부/래퍼 함수 필터 (화이트리스트 미적용)."""
    lowered = api_name.lower()

    if lowered.startswith("fun_"):
        return False

    if lowered.startswith("sub_"):
        return False

    if lowered.startswith("thunk"):
        return False

    if lowered in {"_init", "_fini"}:
        return False

    return True
