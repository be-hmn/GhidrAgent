import argparse
import asyncio
import logging
import os
import subprocess
import sys

from pathlib import Path
from datetime import datetime

from dotenv import load_dotenv

from analyzer.runtime import run_analysis
from analyzer.exporter import export_to_json
from analyzer.mcp_server import main_mcp_server


def configure_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(message)s",
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="GhidraMCP - LLM-Friendly Binary Analysis Framework"
    )

    # 모드 선택
    subparsers = parser.add_subparsers(dest="mode", help="작동 모드")

    # CLI 모드 (기본값)
    cli_parser = subparsers.add_parser("cli", help="CLI 모드 (기본값)")
    cli_parser.add_argument(
        "--ghidra-home",
        help="Override GHIDRA_HOME",
    )
    cli_parser.add_argument(
        "--binary",
        required=False,
        help="Target binary file path (can use TARGET_BINARY env var)",
    )
    cli_parser.add_argument(
        "--output",
        help="Output JSON path (default: output/{binary_name}.json)",
    )
    cli_parser.add_argument(
        "--project-dir",
        help="Override PROJECT_DIR (default: .ghidra_projects)",
    )
    cli_parser.add_argument(
        "--project-name",
        help="Override PROJECT_NAME (default: GhidraMCPProject)",
    )
    cli_parser.add_argument(
        "--timestamp",
        action="store_true",
        help="Add timestamp to output filename",
    )

    # MCP 모드
    mcp_parser = subparsers.add_parser("mcp", help="MCP 서버 모드")
    mcp_parser.add_argument(
        "--stdio",
        action="store_true",
        help="Use stdio transport (default)",
    )
    mcp_parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port for SSE transport (default: 8000)",
    )

    args = parser.parse_args()

    # 기본값: CLI 모드
    if args.mode is None:
        args.mode = "cli"

    return args


def resolve_binary_path(binary_path_str: str) -> Path:
    """바이너리 파일 경로 해석 (확장자 없어도 작동)

    확장자가 없는 경우:
    1. 정확히 그 파일이 있는지 확인
    2. 없으면 흔한 확장자 자동 추가 시도 (.exe, .elf, .bin)

    Args:
        binary_path_str: 바이너리 경로 (확장자 있을 수도, 없을 수도)

    Returns:
        존재하는 바이너리 파일 경로

    Raises:
        FileNotFoundError: 파일을 찾을 수 없음

    Examples:
        "easy_crack.exe" → /path/to/easy_crack.exe
        "easy_crack" → /path/to/easy_crack (파일 있으면)
        "malware" → /path/to/malware.elf (malware.exe 없으면 시도)
    """

    path = Path(binary_path_str).resolve()

    logging.debug("Trying to resolve binary path: %s", path)

    # 1. 정확히 그 파일이 있는지 확인
    if path.exists() and path.is_file():
        logging.debug("Binary found (exact match): %s", path)
        return path

    # 2. 파일이 없으면 흔한 확장자 시도
    common_extensions = [
        ".exe",
        ".elf",
        ".bin",
        ".o",
        ".so",
        ".dylib",
        ".dll",
        ".sys",
    ]

    for ext in common_extensions:
        candidate = path.parent / (path.name + ext)

        logging.debug("Trying extension: %s", candidate)

        if candidate.exists() and candidate.is_file():
            logging.info(
                "Binary file found with extension: %s",
                candidate.name
            )
            return candidate

    # 3. 아무것도 찾지 못함
    raise FileNotFoundError(
        f"Binary file not found: {path}\n"
        f"Tried: {path.name}, "
        f"{path.name}.exe, {path.name}.elf, {path.name}.bin, ..."
    )


def generate_output_path(
        binary_path: Path,
        args_output: str = None,
        add_timestamp: bool = False,
) -> Path:
    """바이너리 이름을 기반으로 output 경로 생성

    Args:
        binary_path: 바이너리 파일 경로
        args_output: CLI에서 명시적으로 지정된 output 경로
        add_timestamp: 타임스탬프 추가 여부

    Returns:
        생성된 output 파일 경로

    Examples:
        binary_path="/path/to/easy_crack.exe"
        → "output/easy_crack.json"

        binary_path="/path/to/Easy_ELF" (no extension)
        → "output/Easy_ELF.json"

        binary_path="/path/to/malware.elf", add_timestamp=True
        → "output/malware_2026-05-13_20-44-38.json"
    """

    # 명시적으로 지정된 경로가 있으면 그것 사용
    if args_output:
        return Path(args_output).resolve()

    # 바이너리 이름 (확장자 포함/제외 모두 처리)
    # easy_crack.exe → easy_crack
    # Easy_ELF → Easy_ELF
    binary_name = binary_path.stem

    # 타임스탬프 추가 (선택사항)
    if add_timestamp:
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        filename = f"{binary_name}_{timestamp}.json"
    else:
        filename = f"{binary_name}.json"

    # output 디렉토리 생성 및 파일 경로 반환
    output_dir = Path("output").resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    output_path = output_dir / filename

    return output_path


def generate_project_name(
        binary_path: Path,
        project_name_template: str = None,
) -> str:
    """Generate a Ghidra project name from a template and binary metadata."""

    template = project_name_template or "GhidraMCPProject_{binary_name}"
    values = {
        "binary_name": binary_path.stem,
        "binary_stem": binary_path.stem,
        "binary_file": binary_path.name,
        "binary_suffix": binary_path.suffix.lstrip("."),
    }

    try:
        return template.format(**values)
    except KeyError as e:
        supported = ", ".join(sorted(values))
        raise ValueError(
            f"Unsupported PROJECT_NAME placeholder: {{{e.args[0]}}}. "
            f"Supported placeholders: {supported}"
        ) from e


def load_config(
        args: argparse.Namespace,
) -> dict:
    """설정 로드 (환경 변수 + CLI 옵션)"""

    # ⭐ .env 파일 먼저 로드
    load_dotenv(verbose=True, override=True)

    # 바이너리 경로 (필수)
    binary_path_str = getattr(args, 'binary', None) or os.getenv("TARGET_BINARY")

    if not binary_path_str:
        raise ValueError(
            "Binary path is required: use --binary option or set TARGET_BINARY env var"
        )

    logging.info("Binary path from config: %s", binary_path_str)

    # 바이너리 경로 해석 (확장자 자동 추가 시도)
    try:
        binary_path = resolve_binary_path(binary_path_str)
    except FileNotFoundError as e:
        logging.error("Failed to resolve binary path: %s", str(e))
        raise

    logging.info("Binary file resolved: %s", binary_path)

    # Output 경로 생성 (auto-generate from binary name)
    output_path = generate_output_path(
        binary_path=binary_path,
        args_output=getattr(args, 'output', None) or os.getenv("OUTPUT_PATH"),
        add_timestamp=getattr(args, 'timestamp', False),
    )

    logging.info("Output path: %s", output_path)

    project_name = generate_project_name(
        binary_path=binary_path,
        project_name_template=getattr(args, 'project_name', None) or os.getenv("PROJECT_NAME"),
    )

    config = {
        "ghidra_home": (
                getattr(args, 'ghidra_home', None)
                or os.getenv("GHIDRA_HOME")
        ),

        "binary": str(binary_path),

        "output": str(output_path),

        "project_dir": (
                getattr(args, 'project_dir', None)
                or os.getenv(
            "PROJECT_DIR",
            ".ghidra_projects",
        )
        ),

        "project_name": (
                project_name
        ),
    }

    required = [
        "ghidra_home",
        "binary",
    ]

    missing = [
        key
        for key in required
        if not config[key]
    ]

    if missing:
        raise ValueError(
            f"Missing configuration: {missing}"
        )

    logging.info("Configuration loaded successfully")
    logging.debug("Config: %s", {k: v for k, v in config.items() if k != "binary"})

    return config


def validate_paths(
        ghidra_home: Path,
        binary_path: Path,
) -> None:
    """경로 검증"""

    if not ghidra_home.exists():
        raise FileNotFoundError(
            f"Ghidra home not found: {ghidra_home}"
        )

    if not binary_path.exists():
        raise FileNotFoundError(
            f"Binary not found: {binary_path}"
        )

    if not binary_path.is_file():
        raise ValueError(
            f"Target is not file: {binary_path}"
        )


def validate_mcp_output(
        output_path: Path,
) -> None:
    """Run scripts/mcp_smoke.py against the exported MCP JSON."""

    logging.info("Running MCP smoke validation: %s", output_path)

    smoke_script = Path(__file__).resolve().parent / "scripts" / "mcp_smoke.py"
    completed = subprocess.run(
        [
            sys.executable,
            str(smoke_script),
            "--input",
            str(output_path),
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    stdout = completed.stdout.strip()
    stderr = completed.stderr.strip()

    if completed.returncode != 0:
        logging.error("MCP smoke validation failed")
        if stdout:
            logging.error(stdout)
        if stderr:
            logging.error(stderr)
        raise ValueError(
            f"MCP smoke validation failed: {output_path}"
        )

    if stdout:
        logging.info(stdout)


def main() -> None:
    configure_logging()

    args = parse_args()

    if args.mode == "mcp":
        _main_mcp(args)
    else:
        _main_cli(args)


def _main_cli(args: argparse.Namespace) -> None:
    """CLI 모드 메인 함수"""
    try:
        config = load_config(args)
    except (ValueError, FileNotFoundError) as e:
        logging.error("Configuration error: %s", str(e))
        raise

    ghidra_home = Path(
        config["ghidra_home"]
    ).resolve()

    binary_path = Path(
        config["binary"]
    ).resolve()

    output_path = Path(
        config["output"]
    ).resolve()

    project_dir = Path(
        config["project_dir"]
    ).resolve()

    project_name = config["project_name"]

    try:
        validate_paths(
            ghidra_home,
            binary_path,
        )
    except FileNotFoundError as e:
        logging.error("Path validation error: %s", str(e))
        raise

    logging.info(
        "Starting analysis: %s → %s",
        binary_path.name,
        output_path.name,
    )

    results = run_analysis(
        ghidra_home=ghidra_home,
        binary_path=binary_path,
        project_dir=project_dir,
        project_name=project_name,
    )

    export_to_json(
        results,
        output_path,
    )

    logging.info(
        "Analysis complete: %d functions → %s",
        len(results),
        output_path.name,
    )

    validate_mcp_output(output_path)


def _main_mcp(args: argparse.Namespace) -> None:
    """MCP 서버 모드 메인 함수"""
    logging.info("Starting MCP server mode")
    
    # asyncio 이벤트 루프에서 서버 실행
    try:
        asyncio.run(main_mcp_server())
    except KeyboardInterrupt:
        logging.info("MCP server shut down")
    except Exception as e:
        logging.exception(f"MCP server error: {e}")
        raise


if __name__ == "__main__":
    main()
