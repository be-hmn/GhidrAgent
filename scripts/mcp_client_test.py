"""MCP 클라이언트 테스트 스크립트"""

import asyncio
import json
import sys
from pathlib import Path

# MCP 클라이언트 SDK import (필요시 설치)
try:
    from mcp import ClientSession
    from mcp.client.stdio import StdioClientTransport
except ImportError:
    print("Error: MCP client SDK not installed")
    print("Install with: pip install mcp")
    sys.exit(1)


async def test_mcp_analyze():
    """MCP 서버의 analyze_binary 도구 테스트"""

    # 테스트용 바이너리 경로 설정
    test_binary = Path(".binary/target.exe")
    ghidra_home = Path("C:/Program Files/ghidra_11.0.1")  # 실제 경로로 수정 필요

    if not test_binary.exists():
        print(f"Test binary not found: {test_binary}")
        return

    if not ghidra_home.exists():
        print(f"Ghidra home not found: {ghidra_home}")
        print("Please set correct GHIDRA_HOME path")
        return

    # MCP 서버에 연결 (stdio 모드)
    # Note: 서버가 별도 프로세스로 실행 중이어야 함
    # $ python main.py mcp --stdio

    try:
        # 실제 테스트는 MCP 서버가 실행 중일 때 수동으로 수행
        print("MCP 클라이언트 테스트 스크립트")
        print("=" * 50)
        print()
        print("사용법:")
        print("1. 터미널 1에서 MCP 서버 시작:")
        print("   python main.py mcp")
        print()
        print("2. 터널 2에서 클라이언트 테스트:")
        print("   python scripts/mcp_client_test.py")
        print()
    except Exception as e:
        print(f"Error: {e}")


async def test_mcp_validate():
    """MCP 서버의 validate_mcp_output 도구 테스트"""

    test_output = Path("output/Easy_CrackMe.json")

    if not test_output.exists():
        print(f"Test output not found: {test_output}")
        return


if __name__ == "__main__":
    asyncio.run(test_mcp_analyze())

