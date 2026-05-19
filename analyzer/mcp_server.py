"""MCP 서버 구현 - GhidraMCP MCP Interface (MCP SDK 1.27+)"""

import asyncio
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from mcp.server import Server
from mcp.types import Resource, TextContent, Tool, ToolResultContent

from analyzer.runtime import run_analysis
from analyzer.exporter import _mcp_row
from analyzer.project_manager import ProjectLockManager

logger = logging.getLogger(__name__)


class DateTimeEncoder(json.JSONEncoder):
    """datetime 객체를 처리하는 JSON 인코더"""

    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)


async def main_mcp_server():
    """MCP 서버 메인 함수"""
    from mcp.server.stdio import stdio_server

    server = Server("ghidragent")
    project_manager = ProjectLockManager()

    @server.list_resources()
    async def list_resources() -> List[Resource]:
        """사용 가능한 리소스 목록 반환"""
        return [
            Resource(
                uri="ghidra://binaries",
                name="Available Binaries",
                description="List of analyzed binaries",
                mimeType="application/json",
            ),
        ]

    @server.read_resource()
    async def read_resource(uri: str) -> str:
        """리소스 읽기"""
        if uri == "ghidra://binaries":
            return json.dumps(
                project_manager.list_analyzed_binaries(),
                cls=DateTimeEncoder
            )
        raise ValueError(f"Unknown resource: {uri}")

    @server.list_tools()
    async def list_tools() -> List[Tool]:
        """사용 가능한 도구 목록 반환"""
        return [
            Tool(
                name="analyze_binary",
                description="Analyze binary file with Ghidra",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "ghidra_home": {
                            "type": "string",
                            "description": "Path to Ghidra installation"
                        },
                        "binary_path": {
                            "type": "string",
                            "description": "Path to binary file"
                        },
                        "project_dir": {
                            "type": "string",
                            "description": "Ghidra project directory (default: .ghidra_projects)"
                        },
                        "project_name": {
                            "type": "string",
                            "description": "Project name (default: auto-generated)"
                        },
                    },
                    "required": ["ghidra_home", "binary_path"]
                }
            ),
            Tool(
                name="get_analysis_result",
                description="Get cached analysis result for a binary",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "binary_path": {
                            "type": "string",
                            "description": "Path to analyzed binary"
                        }
                    },
                    "required": ["binary_path"]
                }
            ),
            Tool(
                name="validate_mcp_output",
                description="Validate MCP JSON output format",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "output_path": {
                            "type": "string",
                            "description": "Path to MCP JSON file"
                        }
                    },
                    "required": ["output_path"]
                }
            ),
        ]

    @server.call_tool()
    async def call_tool(name: str, arguments: Dict[str, Any]) -> List[ToolResultContent]:
        """도구 실행"""
        try:
            if name == "analyze_binary":
                return await handle_analyze_binary(arguments, project_manager)
            elif name == "get_analysis_result":
                return await handle_get_analysis_result(arguments, project_manager)
            elif name == "validate_mcp_output":
                return await handle_validate_mcp_output(arguments)
            else:
                return [ToolResultContent(
                    type="text",
                    text=json.dumps({"error": f"Unknown tool: {name}"})
                )]
        except Exception as e:
            logger.exception(f"Tool error: {e}")
            return [ToolResultContent(
                type="text",
                text=json.dumps({"error": str(e)})
            )]

    # stdio 모드로 서버 실행
    logger.info("GhidraMCP MCP Server started (stdio mode)")
    await stdio_server(server)


async def handle_analyze_binary(
    arguments: Dict[str, Any],
    project_manager: ProjectLockManager
) -> List[ToolResultContent]:
    """바이너리 분석 핸들러"""
    ghidra_home = Path(arguments.get("ghidra_home")).resolve()
    binary_path = Path(arguments.get("binary_path")).resolve()
    project_dir = Path(arguments.get("project_dir", ".ghidra_projects")).resolve()
    project_name = arguments.get(
        "project_name",
        f"GhidraMCPProject_{binary_path.stem}"
    )

    # 인자 검증
    if not binary_path.exists():
        return [ToolResultContent(
            type="text",
            text=json.dumps({"error": f"Binary not found: {binary_path}"})
        )]

    if not ghidra_home.exists():
        return [ToolResultContent(
            type="text",
            text=json.dumps({"error": f"Ghidra home not found: {ghidra_home}"})
        )]

    try:
        # 프로젝트 잠금 획득
        with project_manager.acquire_lock(project_name):
            logger.info(f"Starting analysis: {binary_path}")

            # 분석 실행 (스레드에서 수행)
            results = await asyncio.to_thread(
                run_analysis,
                ghidra_home,
                binary_path,
                project_dir,
                project_name,
            )

            # 결과 캐싱
            project_manager.cache_analysis(str(binary_path), results)

            # MCP 형식으로 변환
            mcp_data = {
                "metadata": {
                    "version": "2.1",
                    "total_functions": len(results),
                    "export_format": "mcp_min",
                    "binary": str(binary_path),
                },
                "functions": [_mcp_row(row) for row in results],
            }

            logger.info(f"Analysis complete: {len(results)} functions")

            return [ToolResultContent(
                type="text",
                text=json.dumps(mcp_data, ensure_ascii=False, indent=2, cls=DateTimeEncoder)
            )]

    except Exception as e:
        logger.exception(f"Analysis failed: {e}")
        return [ToolResultContent(
            type="text",
            text=json.dumps({"error": f"Analysis failed: {str(e)}"})
        )]


async def handle_get_analysis_result(
    arguments: Dict[str, Any],
    project_manager: ProjectLockManager
) -> List[ToolResultContent]:
    """분석 결과 조회 핸들러"""
    binary_path = arguments.get("binary_path")

    cached_result = project_manager.get_cached_analysis(binary_path)

    if cached_result is None:
        return [ToolResultContent(
            type="text",
            text=json.dumps({"error": f"No cached result for: {binary_path}"})
        )]

    mcp_data = {
        "metadata": {
            "version": "2.1",
            "total_functions": len(cached_result),
            "export_format": "mcp_min",
            "binary": binary_path,
        },
        "functions": [_mcp_row(row) for row in cached_result],
    }

    return [ToolResultContent(
        type="text",
        text=json.dumps(mcp_data, ensure_ascii=False, indent=2, cls=DateTimeEncoder)
    )]


async def handle_validate_mcp_output(
    arguments: Dict[str, Any]
) -> List[ToolResultContent]:
    """MCP 출력 검증"""
    output_path = Path(arguments.get("output_path")).resolve()

    if not output_path.exists():
        return [ToolResultContent(
            type="text",
            text=json.dumps({"error": f"File not found: {output_path}"})
        )]

    try:
        with output_path.open("r", encoding="utf-8") as fp:
            payload = json.load(fp)

        errors = validate_mcp_payload(payload)

        if errors:
            return [ToolResultContent(
                type="text",
                text=json.dumps({"errors": errors})
            )]

        func_count = len(payload.get("functions", []))
        return [ToolResultContent(
            type="text",
            text=json.dumps({"status": "ok", "function_count": func_count})
        )]

    except Exception as e:
        logger.exception(f"Validation error: {e}")
        return [ToolResultContent(
            type="text",
            text=json.dumps({"error": f"Validation error: {str(e)}"})
        )]


def validate_mcp_payload(payload: Dict) -> List[str]:
    """MCP 페이로드 검증"""
    REQUIRED_FIELDS = {
        "name", "body_size", "calls", "called_by",
        "api_calls", "strings", "parameters", "return_type",
        "metrics", "call_sequence",
    }

    errors: List[str] = []

    if "functions" not in payload or not isinstance(payload["functions"], list):
        errors.append("Missing or invalid 'functions' list")
        return errors

    for idx, func in enumerate(payload["functions"]):
        missing = REQUIRED_FIELDS - set(func.keys())
        if missing:
            errors.append(
                f"functions[{idx}] missing fields: {sorted(missing)}"
            )

    return errors


def create_mcp_server() -> Server:
    """MCP 서버 생성 (호환성)"""
    # 이 함수는 호환성을 위해 유지
    # 실제 서버는 main_mcp_server()를 asyncio.run()으로 호출
    return None  # Server 객체를 반환하지 않음
