"""Validation constraint extraction from decompiled code."""

import logging
import re
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

CHAR_COMPARE_RE = re.compile(
    r"\b(?P<var>[A-Za-z_]\w*)\s*"
    r"(?P<op>==|!=)\s*"
    r"'(?P<char>(?:\\.|[^'\\]))'"
)
CALL_COMPARE_RE = re.compile(
    r"\b(?P<func>_?strn?cmp|memcmp)\s*"
    r"\(\s*(?P<left>[^,]+?)\s*,\s*(?P<right>[^,]+?)\s*,\s*"
    r"(?P<size>0x[0-9a-fA-F]+|\d+)\s*\)"
)
INPUT_CALL_RE = re.compile(
    r"\b(?:GetDlgItemTextA|GetDlgItemTextW|fgets|gets|scanf|read)\s*"
    r"\([^;]*?&(?P<base>[A-Za-z_]\w*)"
)
STACK_SUFFIX_RE = re.compile(r"(?:Stack|local)_?([0-9a-fA-F]+)$", re.IGNORECASE)
DAT_SYMBOL_RE = re.compile(r"\bDAT_[0-9a-fA-F]+\b")


def extract_validation_constraints(
        decompiled_code: Optional[str],
        resolved_data: List[Dict],
) -> List[Dict]:
    """Extract simple validation constraints from decompiled C code."""
    if not decompiled_code:
        return []

    resolved_by_symbol = {
        item.get("symbol", "").lower(): item
        for item in resolved_data
        if isinstance(item, dict)
    }
    input_base = find_input_base_variable(decompiled_code)

    constraints = []
    constraints.extend(
        extract_char_comparisons(decompiled_code, input_base)
    )
    constraints.extend(
        extract_call_comparisons(
            decompiled_code,
            resolved_by_symbol,
            input_base,
        )
    )

    return dedupe_constraints(constraints)


def extract_char_comparisons(
        decompiled_code: str,
        input_base: Optional[str],
) -> List[Dict]:
    """Extract constraints such as cStack_63 == 'a'."""
    constraints = []

    for match in CHAR_COMPARE_RE.finditer(decompiled_code):
        var_name = match.group("var")
        value = decode_c_char(match.group("char"))
        context = context_for_position(decompiled_code, match.start())

        constraints.append({
            "kind": "char_compare",
            "operator": match.group("op"),
            "target": var_name,
            "value": value,
            "input_index": infer_input_index(input_base, var_name),
            "source": "decompiled_char_comparison",
            "confidence": "medium",
            "context": compact_context(context),
        })

    return constraints


def extract_call_comparisons(
        decompiled_code: str,
        resolved_by_symbol: Dict[str, Dict],
        input_base: Optional[str],
) -> List[Dict]:
    """Extract constraints from strcmp/strncmp/memcmp style calls."""
    constraints = []

    for match in CALL_COMPARE_RE.finditer(decompiled_code):
        left = match.group("left").strip()
        right = match.group("right").strip()
        size = parse_int(match.group("size"))
        context = context_for_position(decompiled_code, match.start())
        symbol = find_dat_symbol(left) or find_dat_symbol(right)
        resolved = resolved_by_symbol.get(symbol.lower()) if symbol else None
        target_expr = right if find_dat_symbol(left) else left

        constraints.append({
            "kind": "buffer_compare",
            "function": match.group("func"),
            "target": target_expr,
            "symbol": symbol,
            "value": resolved.get("value") if resolved else None,
            "length": size,
            "input_index": infer_input_index_from_expression(input_base, target_expr),
            "source": "decompiled_compare_call",
            "confidence": "medium" if resolved else "low",
            "context": compact_context(context),
        })

    return constraints


def find_input_base_variable(decompiled_code: str) -> Optional[str]:
    """Find the local variable used as the base of an input buffer."""
    match = INPUT_CALL_RE.search(decompiled_code)
    if not match:
        return None
    return match.group("base")


def infer_input_index(
        input_base: Optional[str],
        var_name: str,
) -> Optional[int]:
    """Infer input index from stack/local variable suffixes when possible."""
    if not input_base:
        return None

    base_offset = stack_offset(input_base)
    var_offset = stack_offset(var_name)

    if base_offset is None or var_offset is None:
        return None

    index = base_offset - var_offset
    return index if index >= 0 else None


def infer_input_index_from_expression(
        input_base: Optional[str],
        expression: str,
) -> Optional[int]:
    """Infer input index from an expression such as &cStack_62 or acStack_61 + 1."""
    if not input_base:
        return None

    names = re.findall(r"\b[A-Za-z_]\w*\b", expression)
    for name in names:
        index = infer_input_index(input_base, name)
        if index is None:
            continue

        plus_match = re.search(rf"\b{name}\b\s*\+\s*(0x[0-9a-fA-F]+|\d+)", expression)
        if plus_match:
            index += parse_int(plus_match.group(1))

        return index

    return None


def stack_offset(var_name: str) -> Optional[int]:
    """Extract numeric offset from names like CStack_64, cStack_63, local_64."""
    match = STACK_SUFFIX_RE.search(var_name)
    if not match:
        return None

    text = match.group(1)
    try:
        return int(text, 16 if any(c in "abcdefABCDEF" for c in text) else 10)
    except ValueError:
        return None


def parse_int(value: str) -> int:
    """Parse decimal or hex integer strings."""
    return int(value, 16 if value.lower().startswith("0x") else 10)


def decode_c_char(value: str) -> str:
    """Decode common C character escapes."""
    escapes = {
        r"\0": "\0",
        r"\n": "\n",
        r"\r": "\r",
        r"\t": "\t",
        r"\\": "\\",
        r"\'": "'",
    }
    return escapes.get(value, value)


def find_dat_symbol(expression: str) -> Optional[str]:
    """Find a DAT_xxx symbol in an expression."""
    match = DAT_SYMBOL_RE.search(expression)
    return match.group(0) if match else None


def context_for_position(
        decompiled_code: str,
        position: int,
        radius: int = 1,
) -> str:
    """Return a small line window around a source position."""
    lines = decompiled_code.splitlines()
    current_offset = 0

    for index, line in enumerate(lines):
        next_offset = current_offset + len(line) + 1
        if current_offset <= position < next_offset:
            start = max(0, index - radius)
            end = min(len(lines), index + radius + 1)
            return "\n".join(lines[start:end])
        current_offset = next_offset

    return ""


def compact_context(context: str) -> str:
    """Normalize context for compact JSON output."""
    return " ".join(line.strip() for line in context.splitlines() if line.strip())


def dedupe_constraints(constraints: List[Dict]) -> List[Dict]:
    """Deduplicate constraints while preserving order."""
    results = []
    seen = set()

    for constraint in constraints:
        key = (
            constraint.get("kind"),
            constraint.get("target"),
            constraint.get("operator"),
            constraint.get("value"),
            constraint.get("symbol"),
            constraint.get("input_index"),
        )
        if key in seen:
            continue
        seen.add(key)
        results.append(constraint)

    return results
