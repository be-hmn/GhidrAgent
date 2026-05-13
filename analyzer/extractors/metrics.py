"""함수 복잡도 및 메트릭 계산"""

import logging
from typing import Dict

logger = logging.getLogger(__name__)


def extract_metrics(flat_api, func) -> Dict:
    """함수 메트릭 추출

    Returns:
        dict: {
            "num_instructions": int,
            "num_basic_blocks": int,
            "cyclomatic_complexity": int,
            "is_leaf_function": bool,
            "is_entry_point": bool
        }
    """
    program = flat_api.getCurrentProgram()
    listing = program.getListing()

    return {
        "num_instructions": count_instructions(listing, func),
        "num_basic_blocks": count_basic_blocks(func),
        "cyclomatic_complexity": calculate_cyclomatic_complexity(func),
        "is_leaf_function": is_leaf_function(func),
        "is_entry_point": is_entry_point(func),
    }


def count_instructions(listing, func) -> int:
    """함수 내 instruction 개수 계산"""
    try:
        count = 0
        instructions = listing.getInstructions(func.getBody(), True)

        while instructions.hasNext():
            instructions.next()
            count += 1

        return count

    except Exception as e:
        logger.debug(f"Failed to count instructions: {e}")
        return 0


def count_basic_blocks(func) -> int:
    """Basic Block 개수 (대략적 계산)

    조건 분기의 개수 + 1로 대략 계산
    정확한 계산은 CFG 구성 필요
    """
    try:
        # 간단한 추정: 조건 분기 명령어(jcc) 개수 + 1
        program = func.getProgram()
        listing = program.getListing()

        branch_count = 0
        instructions = listing.getInstructions(func.getBody(), True)

        while instructions.hasNext():
            instr = instructions.next()
            mnemonic = instr.getMnemonicString().lower()

            # 조건 분기 명령어 감지
            if any(br in mnemonic for br in ["j", "call", "ret"]):
                branch_count += 1

        return max(1, branch_count)

    except Exception as e:
        logger.debug(f"Failed to count basic blocks: {e}")
        return 1


def calculate_cyclomatic_complexity(func) -> int:
    """Cyclomatic Complexity 계산

    CC = E - N + 2P
    E: 엣지 수, N: 노드 수, P: 연결 요소 수 (대부분 1)

    단순화: 조건 분기 개수 + 1
    """
    try:
        program = func.getProgram()
        listing = program.getListing()

        # 조건 분기 명령어 개수
        decision_points = 0
        instructions = listing.getInstructions(func.getBody(), True)

        conditional_branches = [
            "je", "jne", "jz", "jnz",  # 같음/다름
            "jg", "jge", "jl", "jle",  # 부호 있는 비교
            "ja", "jae", "jb", "jbe",  # 부호 없는 비교
            "jo", "jno", "jp", "jnp",  # 오버플로우, 패리티
            "js", "jns",               # 부호
            "loop", "jcxz",            # 루프
        ]

        while instructions.hasNext():
            instr = instructions.next()
            mnemonic = instr.getMnemonicString().lower()

            if any(branch in mnemonic for branch in conditional_branches):
                decision_points += 1

        # CC = decision_points + 1
        return max(1, decision_points + 1)

    except Exception as e:
        logger.debug(f"Failed to calculate cyclomatic complexity: {e}")
        return 1


def is_leaf_function(func) -> bool:
    """Leaf function 여부 (다른 함수를 호출하지 않음)"""
    try:
        called_functions = list(func.getCalledFunctions(None))
        return len(called_functions) == 0

    except Exception as e:
        logger.debug(f"Failed to check if leaf function: {e}")
        return False


def is_entry_point(func) -> bool:
    """Entry point 함수 여부"""
    func_name = func.getName().lower()

    entry_names = [
        "entry",
        "main",
        "_main",
        "winmain",
        "_winmain",
        "entrypoint",
        "start",
        "_start",
    ]

    return func_name in entry_names