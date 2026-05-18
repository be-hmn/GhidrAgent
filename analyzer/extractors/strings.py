"""String extraction helpers."""

import logging
import re
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

DAT_SYMBOL_RE = re.compile(r"\bDAT_([0-9a-fA-F]+)\b")
VALIDATION_CONTEXT_TOKENS = (
    "strcmp",
    "strncmp",
    "memcmp",
    "strstr",
    "strchr",
    "==",
    "!=",
    "<",
    ">",
)


def extract_strings(flat_api, func) -> List[Dict]:
    """Extract referenced strings from a function.

    Ghidra references can point into the middle of a string. This extractor
    accepts defined string data at or containing the reference target, reads
    from the exact referenced address, then removes shorter suffix candidates
    when a longer nearby candidate explains the same bytes.
    """
    program = flat_api.getCurrentProgram()
    listing = program.getListing()
    ref_mgr = program.getReferenceManager()
    memory = program.getMemory()

    candidates: List[Dict] = []
    seen_locations = set()

    try:
        instructions = listing.getInstructions(func.getBody(), True)

        while instructions.hasNext():
            try:
                instruction = instructions.next()
                refs = ref_mgr.getReferencesFrom(instruction.getAddress())

                for ref in refs:
                    try:
                        target_addr = ref.getToAddress()
                        data = get_string_data_for_address(listing, target_addr)

                        if not data:
                            continue

                        data_type = str(data.getDataType())
                        string_value = extract_string_value(memory, target_addr)

                        if not string_value:
                            continue

                        if not is_valid_string(string_value):
                            logger.debug("Filtered noise string: %s", string_value)
                            continue

                        location_key = (string_value, str(target_addr))
                        if location_key in seen_locations:
                            continue

                        seen_locations.add(location_key)
                        candidates.append({
                            "value": string_value,
                            "address": str(target_addr),
                            "length": len(string_value),
                            "type": data_type,
                            "_offset": address_offset(target_addr),
                        })

                        logger.debug("Extracted string candidate: %s", string_value)

                    except Exception as exc:
                        logger.debug("Failed to process string reference: %s", exc)
                        continue

            except Exception as exc:
                logger.debug("Failed to process instruction: %s", exc)
                continue

    except Exception as exc:
        logger.warning("Failed to extract strings: %s", exc)

    return remove_inner_suffix_strings(candidates)


def extract_strings_legacy(flat_api, func) -> List[str]:
    """Compatibility helper that returns only string values."""
    strings_list = extract_strings(flat_api, func)
    return sorted(set([s["value"] for s in strings_list]))


def extract_resolved_data_from_decompile(
        flat_api,
        decompiled_code: Optional[str],
) -> List[Dict]:
    """Resolve DAT_xxx symbols from decompiled code as short string data."""
    if not decompiled_code:
        return []

    program = flat_api.getCurrentProgram()
    memory = program.getMemory()
    results = []
    seen_addresses = set()

    for match in DAT_SYMBOL_RE.finditer(decompiled_code):
        address_text = match.group(1)
        symbol = f"DAT_{address_text}"
        context = decompile_context_for_match(decompiled_code, match.start())

        if not is_likely_validation_data_context(context):
            logger.debug("Filtered %s outside validation context", symbol)
            continue

        address = get_address(program, address_text)

        if address is None:
            continue

        address_key = str(address)
        if address_key in seen_addresses:
            continue
        seen_addresses.add(address_key)

        value = extract_null_terminated_printable_value(
            memory,
            address,
            min_length=1,
            max_length=256,
        )

        if not value:
            continue

        if not is_valid_resolved_data_value(value):
            logger.debug("Filtered DAT_%s value: %s", address_text, value)
            continue

        results.append({
            "symbol": symbol,
            "address": address_key,
            "value": value,
            "length": len(value),
            "type": "null_terminated_data",
            "source": "decompiled_dat_reference",
            "confidence": "medium",
            "context": compact_context(context),
        })

    return dedupe_resolved_data(results)


def decompile_context_for_match(
        decompiled_code: str,
        position: int,
        radius: int = 2,
) -> str:
    """Return a small line window around a DAT_xxx occurrence."""
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


def is_likely_validation_data_context(context: str) -> bool:
    """Return whether DAT_xxx is used near comparison or validation logic."""
    lowered = context.lower()

    if not lowered:
        return False

    if any(token in lowered for token in VALIDATION_CONTEXT_TOKENS):
        return True

    if "if (" in lowered or "while (" in lowered:
        return True

    return False


def compact_context(context: str) -> str:
    """Normalize context for compact JSON output."""
    return " ".join(line.strip() for line in context.splitlines() if line.strip())


def get_address(program, address_text: str):
    """Convert a hex address string from a DAT_xxx symbol into a Ghidra Address."""
    try:
        address_space = program.getAddressFactory().getDefaultAddressSpace()
        return address_space.getAddress(int(address_text, 16))
    except Exception as exc:
        logger.debug("Failed to parse DAT_%s address: %s", address_text, exc)
        return None


def extract_null_terminated_printable_value(
        memory,
        address,
        min_length: int = 1,
        max_length: int = 256,
) -> Optional[str]:
    """Read printable bytes until NULL, allowing very short strings."""
    bytes_list = []

    try:
        for i in range(max_length):
            byte = memory.getByte(address.add(i)) & 0xFF

            if byte == 0:
                break

            if not is_printable_string_byte(byte):
                return None

            bytes_list.append(byte)

    except Exception as exc:
        logger.debug("Failed to read resolved data at %s: %s", address, exc)
        return None

    if len(bytes_list) < min_length:
        return None

    try:
        return bytes(bytes_list).decode("utf-8", errors="ignore")
    except Exception:
        return bytes(bytes_list).decode("latin-1", errors="ignore")


def is_valid_resolved_data_value(value: str) -> bool:
    """Filter DAT_xxx resolved values while allowing short strings like '5y'."""
    if not value:
        return False

    if value.strip() == "":
        return False

    if value.startswith(("0x", "0X", "-0x")):
        return False

    if not any(c.isalpha() for c in value):
        return False

    if len(value) >= 4 and is_noise_pattern(value):
        return False

    return True


def dedupe_resolved_data(items: List[Dict]) -> List[Dict]:
    """Deduplicate resolved DAT entries by address and value."""
    results = []
    seen = set()

    for item in items:
        key = (item.get("address"), item.get("value"))
        if key in seen:
            continue
        seen.add(key)
        results.append(item)

    return results


def get_string_data_for_address(listing, address):
    """Return string-like data defined at or containing an address."""
    try:
        data = listing.getDefinedDataAt(address)
        if data and is_string_type(str(data.getDataType())):
            return data
    except Exception:
        pass

    try:
        data = listing.getDefinedDataContaining(address)
        if data and is_string_type(str(data.getDataType())):
            return data
    except Exception:
        pass

    return None


def extract_string_value(memory, address) -> Optional[str]:
    """Read a null-terminated printable string from memory."""
    try:
        bytes_list = []

        for i in range(1024):
            try:
                byte = memory.getByte(address.add(i)) & 0xFF

                if byte == 0:
                    break

                if not is_printable_string_byte(byte):
                    break

                bytes_list.append(byte)

            except Exception:
                break

        if not bytes_list:
            return None

        try:
            return bytes(bytes_list).decode("utf-8", errors="ignore")
        except Exception:
            return bytes(bytes_list).decode("latin-1", errors="ignore")

    except Exception as exc:
        logger.debug("Failed to extract string value: %s", exc)
        return None


def is_printable_string_byte(byte: int) -> bool:
    """Return whether a byte should be kept in a printable string."""
    if byte in (9, 10, 13):
        return True
    return 32 <= byte <= 126


def is_string_type(data_type: str) -> bool:
    """Return whether a Ghidra data type looks string-like."""
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
    """Filter obvious extraction noise."""
    if not value:
        return False

    if len(value) < 4:
        return False

    if value.startswith(("0x", "0X")):
        return False

    if value.strip() == "":
        return False

    if not any(c.isalpha() for c in value):
        return False

    if is_pure_hex(value):
        return False

    if is_noise_pattern(value):
        return False

    return True


def is_pure_hex(value: str) -> bool:
    """Return whether a string consists only of hex digits."""
    if not value:
        return False

    return all(c in "0123456789abcdefABCDEF" for c in value)


def is_noise_pattern(value: str) -> bool:
    """Detect common non-string noise patterns."""
    if value.startswith("-0x"):
        return True

    if len(value) >= 8 and is_pure_hex(value):
        return True

    if len(set(value)) == 1:
        return True

    if len(value) >= 4:
        pattern = value[:2]
        repeated = pattern * (len(value) // 2)
        if repeated == value[:len(repeated)]:
            return is_pure_hex(pattern) or not any(c.isalpha() for c in pattern)

    return False


def remove_inner_suffix_strings(strings: List[Dict]) -> List[Dict]:
    """Drop shorter strings that are exact suffixes of longer nearby strings."""
    filtered = []

    for item in strings:
        if is_suffix_of_longer_candidate(item, strings):
            logger.debug("Dropped suffix string candidate: %s", item.get("value"))
            continue
        filtered.append(strip_internal_fields(item))

    return dedupe_string_values(filtered)


def is_suffix_of_longer_candidate(item: Dict, strings: List[Dict]) -> bool:
    """Return whether an item is an interior suffix of another candidate."""
    value = item.get("value", "")
    offset = item.get("_offset")

    if offset is None:
        return False

    for other in strings:
        if item is other:
            continue

        other_value = other.get("value", "")
        other_offset = other.get("_offset")

        if other_offset is None:
            continue
        if len(value) >= len(other_value):
            continue
        if not other_value.endswith(value):
            continue

        expected_offset = other_offset + len(other_value) - len(value)
        if offset == expected_offset:
            return True

    return False


def address_offset(address) -> Optional[int]:
    """Best-effort conversion of a Ghidra Address to an integer offset."""
    try:
        return int(address.getOffset())
    except Exception:
        return None


def strip_internal_fields(item: Dict) -> Dict:
    """Remove extraction-only metadata from a result row."""
    return {
        key: value
        for key, value in item.items()
        if not key.startswith("_")
    }


def dedupe_string_values(strings: List[Dict]) -> List[Dict]:
    """Keep the first occurrence of each extracted string value."""
    results = []
    seen_values = set()

    for item in strings:
        value = item.get("value")
        if value in seen_values:
            continue
        seen_values.add(value)
        results.append(item)

    return results
