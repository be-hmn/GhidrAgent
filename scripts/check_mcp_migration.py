"""MCP 마이그레이션 검증 스크립트"""

import sys
from pathlib import Path

def check_imports():
    """필수 모듈 import 확인"""
    print("=" * 60)
    print("MCP 마이그레이션 검증")
    print("=" * 60)
    print()

    checks = [
        ("Python asyncio", "import asyncio"),
        ("pathlib Path", "from pathlib import Path"),
        ("logging", "import logging"),
        ("pyhidra", "import pyhidra"),
        ("jpype", "import jpype"),
        ("python-dotenv", "from dotenv import load_dotenv"),
    ]

    print("📦 기존 의존성 확인:")
    print()

    for name, import_stmt in checks:
        try:
            exec(import_stmt)
            print(f"  ✓ {name:20} OK")
        except ImportError as e:
            print(f"  ✗ {name:20} MISSING")

    print()
    print("📦 MCP 의존성 확인:")
    print()

    mcp_checks = [
        ("mcp.server", "from mcp.server import Server"),
        ("mcp.types", "from mcp.types import Resource, Tool, TextContent, ToolResult"),
    ]

    mcp_available = True
    for name, import_stmt in mcp_checks:
        try:
            exec(import_stmt)
            print(f"  ✓ {name:30} OK")
        except ImportError:
            print(f"  ✗ {name:30} MISSING")
            mcp_available = False

    if not mcp_available:
        print()
        print("⚠️  MCP SDK가 설치되어 있지 않습니다.")
        print("   설치 방법:")
        print("   $ pip install mcp>=1.0.0")
        print()

    return mcp_available


def check_file_structure():
    """파일 구조 확인"""
    print("📁 파일 구조 확인:")
    print()

    files_to_check = [
        "main.py",
        "pyproject.toml",
        "analyzer/mcp_server.py",
        "analyzer/project_manager.py",
        "analyzer/runtime.py",
        "analyzer/exporter.py",
        "scripts/mcp_smoke.py",
        "scripts/mcp_client_test.py",
    ]

    # 스크립트 디렉토리에서 프로젝트 루트로 이동
    base_path = Path(__file__).parent.parent  # scripts/../ = 프로젝트 루트

    all_exist = True
    for filepath in files_to_check:
        full_path = base_path / filepath
        exists = full_path.exists()
        status = "✓" if exists else "✗"
        print(f"  {status} {filepath}")
        if not exists:
            all_exist = False

    print()
    return all_exist


def check_code_syntax():
    """코드 문법 확인"""
    print("🔍 코드 문법 확인:")
    print()

    files_to_check = [
        "main.py",
        "analyzer/mcp_server.py",
        "analyzer/project_manager.py",
    ]

    # 스크립트 디렉토리에서 프로젝트 루트로 이동
    base_path = Path(__file__).parent.parent
    all_valid = True

    for filepath in files_to_check:
        full_path = base_path / filepath
        if not full_path.exists():
            print(f"  ✗ {filepath:40} NOT FOUND")
            all_valid = False
            continue

        try:
            with open(full_path, 'r', encoding='utf-8') as f:
                compile(f.read(), str(full_path), 'exec')
            print(f"  ✓ {filepath:40} OK")
        except SyntaxError as e:
            print(f"  ✗ {filepath:40} SYNTAX ERROR")
            print(f"     {e}")
            all_valid = False

    print()
    return all_valid


def check_imports_in_modules():
    """모듈 import 순환 확인"""
    print("🔗 모듈 import 확인:")
    print()

    import sys
    from pathlib import Path

    # 프로젝트 루트를 Python path에 추가
    project_root = Path(__file__).parent.parent
    sys.path.insert(0, str(project_root))

    try:
        print("  Checking: analyzer.project_manager")
        from analyzer.project_manager import ProjectLockManager
        print("    ✓ ProjectLockManager imported")

        print("  Checking: analyzer.mcp_server")
        from analyzer.mcp_server import create_mcp_server
        print("    ✓ create_mcp_server imported")

        print("  Checking: main")
        import main
        print("    ✓ main imported")

        print()
        return True

    except ImportError as e:
        print(f"  ✗ Import error: {e}")
        print()
        return False


def main():
    """메인 확인 로직"""
    print()

    # 1. Import 확인
    mcp_available = check_imports()
    print()

    # 2. 파일 구조 확인
    files_exist = check_file_structure()
    print()

    # 3. 코드 문법 확인
    syntax_ok = check_code_syntax()

    # 4. 모듈 import 확인
    modules_ok = check_imports_in_modules()

    # 결과 출력
    print("=" * 60)
    print("검증 결과:")
    print("=" * 60)
    print()
    print(f"  의존성 설치:     {'✓ OK' if mcp_available else '✗ MCP SDK 필요'}")
    print(f"  파일 구조:      {'✓ OK' if files_exist else '✗ 파일 누락'}")
    print(f"  코드 문법:      {'✓ OK' if syntax_ok else '✗ 문법 에러'}")
    print(f"  모듈 import:    {'✓ OK' if modules_ok else '✗ Import 에러'}")
    print()

    if mcp_available and files_exist and syntax_ok and modules_ok:
        print("🎉 모든 검증 완료! MCP 마이그레이션 준비 완료")
        print()
        print("다음 단계:")
        print("  1. CLI 모드 테스트:")
        print("     $ python main.py cli --binary <binary_path>")
        print()
        print("  2. MCP 서버 시작:")
        print("     $ python main.py mcp")
        print()
        return 0
    else:
        print("⚠️  일부 검증이 실패했습니다. 위 항목들을 확인해주세요.")
        print()
        return 1


if __name__ == "__main__":
    sys.exit(main())

