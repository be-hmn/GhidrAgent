"""MCP 출력 JSON의 기본 스키마를 간단히 검증합니다."""

import argparse
import json
import sys
from pathlib import Path

REQUIRED_FUNCTION_FIELDS = {
    "name",
    "body_size",
    "calls",
    "called_by",
    "api_calls",
    "strings",
    "parameters",
    "return_type",
    "metrics",
    "call_sequence",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate MCP export JSON structure"
    )
    parser.add_argument(
        "--input",
        required=True,
        help="Path to MCP JSON output",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Verbose output",
    )
    return parser.parse_args()


def load_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def validate_payload(payload: dict, verbose: bool = False) -> list[str]:
    """MCP 페이로드 검증

    Args:
        payload: 검증할 JSON 페이로드
        verbose: 상세 메시지 출력

    Returns:
        에러 메시지 리스트
    """
    errors: list[str] = []

    if "functions" not in payload or not isinstance(payload["functions"], list):
        errors.append("Missing or invalid 'functions' list")
        return errors

    for idx, func in enumerate(payload["functions"]):
        missing = REQUIRED_FUNCTION_FIELDS - set(func.keys())
        if missing:
            errors.append(
                f"functions[{idx}] missing fields: {sorted(missing)}"
            )

        if verbose:
            # 상세 검증
            if not isinstance(func.get("name"), str):
                errors.append(f"functions[{idx}].name must be string")
            if not isinstance(func.get("body_size"), int):
                errors.append(f"functions[{idx}].body_size must be integer")
            if not isinstance(func.get("calls"), list):
                errors.append(f"functions[{idx}].calls must be list")

    return errors


def main() -> int:
    args = parse_args()
    input_path = Path(args.input).resolve()

    if not input_path.exists():
        print(f"Input JSON not found: {input_path}")
        return 1

    try:
        payload = load_json(input_path)
        errors = validate_payload(payload, verbose=args.verbose)

        if errors:
            print("Validation failed:")
            for error in errors:
                print(f"- {error}")
            return 1

        func_count = len(payload.get("functions", []))
        metadata = payload.get("metadata", {})

        print(f"✓ Validation passed: {func_count} functions")
        if metadata.get("total_functions"):
            print(f"  Total functions (metadata): {metadata['total_functions']}")
        if metadata.get("version"):
            print(f"  Format version: {metadata['version']}")
        if metadata.get("binary"):
            print(f"  Binary: {metadata['binary']}")

        return 0

    except json.JSONDecodeError as e:
        print(f"Invalid JSON: {e}")
        return 1
    except Exception as e:
        print(f"Error: {e}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

