"""분석 결과를 다양한 형식으로 내보내기"""

import json
import logging
from pathlib import Path
from typing import List, Dict, Optional

logger = logging.getLogger(__name__)


def export_to_json(
        rows: List[Dict],
        output_path: Path,
        compact: bool = False,
) -> None:
    """분석 결과를 JSON으로 내보내기
    
    Args:
        rows: 함수 데이터 리스트
        output_path: 출력 경로
        compact: True이면 압축된 형식 (하위 호환성)
    """

    if output_path.exists() and output_path.is_dir():
        output_path = output_path / "functions.json"

    output_path.parent.mkdir(parents=True, exist_ok=True)

    # MCP 최적화 형식
    if compact:
        export_data = _compact_format(rows)
    else:
        export_data = _full_format(rows)

    try:
        with output_path.open("w", encoding="utf-8") as fp:
            json.dump(
                export_data,
                fp,
                ensure_ascii=False,
                indent=2,
            )

        logger.info(f"Exported {len(rows)} functions to {output_path}")

    except Exception as e:
        logger.error(f"Failed to export to JSON: {e}")
        raise


def _compact_format(rows: List[Dict]) -> List[Dict]:
    """MCP 최소 필드만 포함하는 간결 형식"""
    compact_rows = []

    for row in rows:
        compact_rows.append(_mcp_row(row))

    return compact_rows


def _full_format(rows: List[Dict]) -> Dict:
    """MCP 최적화 형식"""

    return {
        "metadata": {
            "version": "2.1",
            "total_functions": len(rows),
            "export_format": "mcp_min",
        },
        "functions": [_mcp_row(row) for row in rows],
    }


def _mcp_row(row: Dict) -> Dict:
    """MCP용 최소 필드로 정규화"""
    return {
        "name": row.get("name"),
        "body_size": row.get("body_size"),
        "calls": row.get("calls", []),
        "called_by": row.get("called_by", []),
        "api_calls": row.get("api_calls", []),
        "strings": row.get("strings", []),
        "parameters": row.get("parameters", []),
        "return_type": row.get("return_type", "unknown"),
        "metrics": row.get("metrics", {}),
        "call_sequence": row.get("call_sequence", []),
    }


def export_to_json_compact(
        rows: List[Dict],
        output_path: Path,
) -> None:
    """호환성 래퍼: 압축 형식으로 내보내기 (기존 코드와 동일)"""
    export_to_json(rows, output_path, compact=True)


def export_summary(
        rows: List[Dict],
        output_path: Path,
) -> None:
    """분석 요약 정보 내보내기
    
    함수별 통계, 가장 복잡한 함수 등을 정리한 요약 파일
    """

    if output_path.is_dir():
        output_path = output_path / "summary.json"

    output_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        # 통계 계산
        summary = {
            "total_functions": len(rows),
            "functions_with_parameters": sum(
                1 for r in rows if len(r.get("parameters", [])) > 0
            ),
            "functions_with_api_calls": sum(
                1 for r in rows if len(r.get("api_calls", [])) > 0
            ),
            "functions_with_strings": sum(
                1 for r in rows if len(r.get("strings", [])) > 0
            ),
            "total_api_calls": sum(
                len(r.get("api_calls", [])) for r in rows
            ),
            "total_strings_referenced": sum(
                len(r.get("strings", [])) for r in rows
            ),
            "avg_function_size": (
                sum(r.get("body_size", 0) for r in rows) // len(rows)
                if rows else 0
            ),

            # 메트릭 기반 통계
            "functions_by_complexity": _group_by_complexity(rows),
            "most_complex_functions": _get_most_complex(rows, top=10),
            "largest_functions": _get_largest(rows, top=10),
            "most_referenced_api_calls": _get_most_referenced_apis(rows, top=10),
        }

        with output_path.open("w", encoding="utf-8") as fp:
            json.dump(summary, fp, ensure_ascii=False, indent=2)

        logger.info(f"Exported summary to {output_path}")

    except Exception as e:
        logger.error(f"Failed to export summary: {e}")
        raise


def _group_by_complexity(rows: List[Dict]) -> Dict[str, int]:
    """복잡도별 함수 그룹화"""
    groups = {
        "very_simple": 0,      # CC <= 2
        "simple": 0,           # CC 3-5
        "moderate": 0,         # CC 6-10
        "complex": 0,          # CC 11-20
        "very_complex": 0,     # CC > 20
    }

    for row in rows:
        cc = row.get("metrics", {}).get("cyclomatic_complexity", 1)

        if cc <= 2:
            groups["very_simple"] += 1
        elif cc <= 5:
            groups["simple"] += 1
        elif cc <= 10:
            groups["moderate"] += 1
        elif cc <= 20:
            groups["complex"] += 1
        else:
            groups["very_complex"] += 1

    return groups


def _get_most_complex(rows: List[Dict], top: int = 10) -> List[Dict]:
    """가장 복잡한 함수 상위 N개"""
    sorted_rows = sorted(
        rows,
        key=lambda r: r.get("metrics", {}).get("cyclomatic_complexity", 1),
        reverse=True
    )

    return [
        {
            "name": r["name"],
            "cyclomatic_complexity": r.get("metrics", {}).get("cyclomatic_complexity"),
            "body_size": r.get("body_size"),
        }
        for r in sorted_rows[:top]
    ]


def _get_largest(rows: List[Dict], top: int = 10) -> List[Dict]:
    """가장 큰 함수 상위 N개"""
    sorted_rows = sorted(
        rows,
        key=lambda r: r.get("body_size", 0),
        reverse=True
    )

    return [
        {
            "name": r["name"],
            "body_size": r.get("body_size"),
            "num_instructions": r.get("metrics", {}).get("num_instructions"),
        }
        for r in sorted_rows[:top]
    ]


def _get_most_referenced_apis(rows: List[Dict], top: int = 10) -> List[Dict]:
    """가장 자주 호출되는 API 상위 N개"""
    api_count = {}

    for row in rows:
        for api_name in row.get("api_calls", []):
            api_count[api_name] = api_count.get(api_name, 0) + 1

    sorted_apis = sorted(
        api_count.items(),
        key=lambda x: x[1],
        reverse=True
    )

    return [
        {"name": api_name, "call_count": count}
        for api_name, count in sorted_apis[:top]
    ]