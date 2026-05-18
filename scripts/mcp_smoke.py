"""MCP 출력 JSON의 기본 스키마를 간단히 검증합니다."""

import argparse
import json
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
    return parser.parse_args()


def load_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def validate_payload(payload: dict) -> list[str]:
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

    return errors


def main() -> int:
    args = parse_args()
    input_path = Path(args.input).resolve()

    if not input_path.exists():
        print(f"Input JSON not found: {input_path}")
        return 1

    payload = load_json(input_path)
    errors = validate_payload(payload)

    if errors:
        print("Validation failed:")
        for error in errors:
            print(f"- {error}")
        return 1

    func_count = len(payload.get("functions", []))
    print(f"Validation passed: {func_count} functions")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

