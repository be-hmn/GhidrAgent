import argparse
import json
import os
from pathlib import Path
from collections import defaultdict


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run initial Ghidra analysis and export function data to JSON."
    )
    parser.add_argument("--ghidra-home", help="Path to Ghidra installation")
    parser.add_argument("--binary", help="Target binary path")
    parser.add_argument("--output", help="Output JSON path")
    parser.add_argument("--project-dir", help="Temporary project dir")
    parser.add_argument("--project-name", help="Ghidra project name")
    return parser.parse_args()


def extract_call_graph(flat_api, func) -> dict:
    """함수의 호출 그래프 추출 (calls, called_by)"""
    try:
        calls = []
        called_by = []

        # 이 함수가 호출하는 함수들
        for called_func in func.getCalledFunctions(flat_api.monitor):
            calls.append(called_func.getName())

        # 이 함수를 호출하는 함수들
        for caller in func.getCallers(flat_api.monitor):
            called_by.append(caller.getName())

        return {
            'calls': list(set(calls)),  # 중복 제거
            'called_by': list(set(called_by)),  # 중복 제거
        }
    except Exception as e:
        return {'calls': [], 'called_by': []}


def extract_xref_statistics(flat_api, func) -> dict:
    """XREF 통계 추출"""
    try:
        ref_mgr = flat_api.getCurrentProgram().getReferenceManager()

        xrefs_in = 0
        xrefs_out = 0

        # 함수 범위 내의 모든 주소에서의 reference 계산
        for addr in func.getBody():
            # Inbound references
            for ref in ref_mgr.getReferencesTo(addr):
                if ref.isExternalReference() is False:
                    xrefs_in += 1

            # Outbound references
            for ref in ref_mgr.getReferencesFrom(addr):
                if ref.isExternalReference() is False:
                    xrefs_out += 1

        return {
            'xrefs_in': xrefs_in,
            'xrefs_out': xrefs_out,
        }
    except Exception as e:
        return {'xrefs_in': 0, 'xrefs_out': 0}


def extract_api_calls(flat_api, func) -> dict:
    """함수 내에서 사용되는 API 호출 추출"""
    try:
        api_calls = []
        listing = flat_api.getCurrentProgram().getListing()
        ref_mgr = flat_api.getCurrentProgram().getReferenceManager()

        # 함수의 모든 instruction을 순회
        instruction = listing.getInstructionAt(func.getEntryPoint())

        while instruction is not None and func.getBody().contains(instruction.getAddress()):
            # 이 instruction에서의 모든 reference 확인
            for ref in ref_mgr.getReferencesFrom(instruction.getAddress()):
                if ref.isExternalReference():
                    # 외부 심볼 (Import API)
                    symbol = flat_api.getCurrentProgram().getSymbolTable().getSymbol(ref)
                    if symbol:
                        api_name = symbol.getName()
                        api_calls.append(api_name)

            instruction = listing.getInstructionAfter(instruction)

        # 중복 제거
        return {'api_calls': list(set(api_calls))}
    except Exception as e:
        return {'api_calls': []}


def extract_strings(flat_api, func) -> dict:
    """함수에서 참조하는 문자열 추출"""
    try:
        strings = []
        listing = flat_api.getCurrentProgram().getListing()
        ref_mgr = flat_api.getCurrentProgram().getReferenceManager()

        instruction = listing.getInstructionAt(func.getEntryPoint())

        while instruction is not None and func.getBody().contains(instruction.getAddress()):
            for ref in ref_mgr.getReferencesFrom(instruction.getAddress()):
                try:
                    to_addr = ref.getToAddress()
                    data = listing.getDefinedDataAt(to_addr)

                    if data and data.getDataType().getName() == 'string':
                        string_value = data.getValue()
                        if string_value and len(str(string_value)) < 256:  # 너무 긴 문자열 제외
                            strings.append(str(string_value))
                except:
                    pass

            instruction = listing.getInstructionAfter(instruction)

        return {'strings': list(set(strings))}  # 중복 제거
    except Exception as e:
        return {'strings': []}


def calculate_cyclomatic_complexity(flat_api, func) -> int:
    """순환 복잡도 계산"""
    try:
        block_count = 0
        edge_count = 0

        # BasicBlock을 통해 복잡도 추정
        for block in func.getBasicBlocks(flat_api.monitor):
            block_count += 1
            edge_count += len(block.getSuccessors())

        # Cyclomatic Complexity = E - N + 2
        complexity = edge_count - block_count + 2
        return max(1, complexity)  # 최소 1
    except Exception as e:
        return 1


def extract_basic_block_stats(flat_api, func) -> dict:
    """Basic block 통계"""
    try:
        block_count = 0
        edge_count = 0

        for block in func.getBasicBlocks(flat_api.monitor):
            block_count += 1
            edge_count += len(block.getSuccessors())

        return {
            'basic_blocks': block_count,
            'edges': edge_count,
        }
    except Exception as e:
        return {'basic_blocks': 0, 'edges': 0}


def extract_function_signature(flat_api, func) -> dict:
    """함수 시그니처 추출 (파라미터, 반환 타입)"""
    try:
        sig = func.getSignature()
        parameters = []
        return_type = "unknown"

        if sig:
            return_type = str(sig.getReturnType())

            for param in sig.getParameters():
                param_type = str(param.getDataType())
                parameters.append(param_type)

        return {
            'parameters': parameters,
            'return_type': return_type,
        }
    except Exception as e:
        return {'parameters': [], 'return_type': 'unknown'}


def detect_capabilities(api_calls: list, strings: list) -> list:
    """의심스러운 기능 탐지"""
    capabilities = []

    api_lower = [api.lower() for api in api_calls]
    strings_lower = [s.lower() for s in strings]

    # Networking
    if any(api in api_lower for api in ['socket', 'connect', 'send', 'recv', 'wsasocket', 'getaddrinfo']):
        capabilities.append('networking')

    # Crypto
    if any(api in api_lower for api in ['cryptencrypt', 'cryptdecrypt', 'aes', 'rc4', 'md5', 'sha', 'crypt']):
        capabilities.append('crypto')

    # Process Injection
    if any(api in api_lower for api in ['writeprocessmemory', 'createremotethread', 'setwindowshookex']):
        capabilities.append('process_injection')

    # Registry Access
    if any(api in api_lower for api in ['regsetvalueex', 'regcreatekey', 'regdeletekey', 'regopenkey']):
        capabilities.append('registry_access')

    # File Operations
    if any(api in api_lower for api in ['createfilea', 'writefile', 'readfile', 'deletefilea']):
        capabilities.append('file_operations')

    # Persistence
    if any(s in strings_lower for s in ['startup', 'run', 'services', 'scheduled task']):
        capabilities.append('persistence')

    # Anti-debugging
    if any(api in api_lower for api in ['isdebuggerpresent', 'checkremotedebuggerpresent', 'ptrace']):
        capabilities.append('anti_debugging')

    # Unpacking
    if any(api in api_lower for api in ['virtualalloc', 'memcpy', 'memmove', 'virtualprotect']):
        if 'process_injection' not in capabilities:
            capabilities.append('unpacking')

    return list(set(capabilities))  # 중복 제거


def calculate_importance_score(func_data: dict) -> tuple[int, str]:
    """개선된 중요도 점수 계산"""
    body_size = func_data['body_size']
    xrefs_in = func_data['xrefs_in']
    complexity = func_data['complexity']
    api_count = len(func_data['api_calls'])

    # API 위험도 점수
    api_risk_score = min(api_count * 10, 100)

    # 가중 점수 계산
    score = (
            (min(body_size / 10, 100) * 0.2) +  # 크기 (0-100으로 정규화)
            (min(xrefs_in * 5, 100) * 0.3) +     # 참조 (0-100으로 정규화)
            (min(complexity * 2, 100) * 0.3) +   # 복잡도 (0-100으로 정규화)
            (api_risk_score * 0.2)                # API 위험도
    )

    score = int(min(score, 100))

    # 레벨 분류
    if score >= 80:
        level = 'critical'
    elif score >= 60:
        level = 'high'
    elif score >= 40:
        level = 'medium'
    else:
        level = 'low'

    return score, level


def run_analysis_and_export(
        ghidra_home: Path,
        binary_path: Path,
        output_path: Path,
        project_dir: Path,
        project_name: str,
) -> list:
    """
    pyhidra를 사용해 바이너리 분석 및 풍부한 함수 정보 추출
    """
    try:
        import pyhidra
        from pyhidra.launcher import HeadlessPyhidraLauncher
    except ImportError as exc:
        raise RuntimeError(
            "pyhidra is not installed. Run `pip install -r requirements.txt` and retry."
        ) from exc

    print("[1] Initializing HeadlessPyhidraLauncher...")
    launcher = HeadlessPyhidraLauncher(verbose=False, install_dir=ghidra_home)
    print("    ✓ Launcher initialized")

    print("[2] Starting pyhidra (Jpype connection)...")
    launcher.start()
    print("    ✓ Jpype started and Ghidra initialized")

    # 프로젝트 폴더 생성
    print("[2.5] Setting up project directory...")
    project_dir.mkdir(parents=True, exist_ok=True)
    project_path = project_dir / project_name
    project_path.mkdir(parents=True, exist_ok=True)
    print(f"    ✓ Project directory ready: {project_path}")

    print("[3] Creating/Opening Ghidra project...")
    try:
        from jpype.types import JClass

        GhidraProject = JClass("ghidra.base.project.GhidraProject")
        gpr_file = project_path / f"{project_name}.gpr"
        if not gpr_file.exists():
            print(f"    Creating new project: {project_path}")
            project = GhidraProject.createProject(str(project_path), project_name, False)
            project.close()
            print(f"    ✓ Project created: {gpr_file}")
        else:
            print(f"    ✓ Project already exists: {gpr_file}")

    except Exception as e:
        print(f"    ⚠ Project creation warning: {type(e).__name__}: {e}")

    print("[4] Opening binary with pyhidra.open_program()...")
    print(f"    binary_path: {binary_path}")
    print(f"    project_location: {project_dir}")
    print(f"    project_name: {project_name}")

    with pyhidra.open_program(
            str(binary_path),
            project_location=str(project_dir),
            project_name=project_name,
            analyze=True,
    ) as flat_api:
        print("    ✓ Program opened and analyzed")

        print("[5] Extracting enriched function information...")
        program = flat_api.getCurrentProgram()
        listing = program.getListing()
        funcs = listing.getFunctions(True)

        rows = []
        func_count = 0

        for func in funcs:
            func_count += 1
            func_name = func.getName()
            func_entry = str(func.getEntryPoint())
            func_size = func.getBody().getNumAddresses()

            print(f"    [{func_count}] Analyzing {func_name}...")

            # 각 메타데이터 추출
            call_graph = extract_call_graph(flat_api, func)
            xref_stats = extract_xref_statistics(flat_api, func)
            api_calls = extract_api_calls(flat_api, func)['api_calls']
            strings = extract_strings(flat_api, func)['strings']
            complexity = calculate_cyclomatic_complexity(flat_api, func)
            basic_blocks = extract_basic_block_stats(flat_api, func)
            signature = extract_function_signature(flat_api, func)
            capabilities = detect_capabilities(api_calls, strings)

            # 중요도 점수 계산
            func_data = {
                'body_size': func_size,
                'xrefs_in': xref_stats['xrefs_in'],
                'complexity': complexity,
                'api_calls': api_calls,
            }
            importance_score, importance_level = calculate_importance_score(func_data)

            # 최종 데이터
            rows.append({
                'name': func_name,
                'entry': func_entry,
                'body_size': func_size,
                'size_kb': round(func_size / 1024, 3),
                'entry_point_decimal': int(func_entry, 16),

                # Call Graph
                'calls': call_graph['calls'],
                'called_by': call_graph['called_by'],

                # XREF Statistics
                'xrefs_in': xref_stats['xrefs_in'],
                'xrefs_out': xref_stats['xrefs_out'],

                # API and Strings
                'api_calls': api_calls,
                'strings': strings,

                # Complexity Metrics
                'complexity': complexity,
                'basic_blocks': basic_blocks['basic_blocks'],
                'edges': basic_blocks['edges'],

                # Function Signature
                'parameters': signature['parameters'],
                'return_type': signature['return_type'],

                # Capabilities
                'capabilities': capabilities,

                # Importance
                'importance_score': importance_score,
                'importance_level': importance_level,
            })

        print(f"    ✓ Total {len(rows)} functions extracted with enriched metadata")

    print(f"\n[6] Saving enriched analysis data to {output_path}...")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as fp:
        json.dump(rows, fp, ensure_ascii=False, indent=2)
    print(f"    ✓ Saved to {output_path}")

    return rows


def verify_functions(raw_functions: list) -> None:
    """분석 결과 검증"""
    print("\n[verify_functions] Verification Report")
    print("=" * 100)

    print(f"Total functions extracted: {len(raw_functions)}")

    # 중요도 분포
    levels = defaultdict(int)
    for func in raw_functions:
        levels[func['importance_level']] += 1

    print("\nImportance Level Distribution:")
    print(f"  Critical: {levels['critical']}")
    print(f"  High: {levels['high']}")
    print(f"  Medium: {levels['medium']}")
    print(f"  Low: {levels['low']}")

    # 기능 분포
    capabilities_count = defaultdict(int)
    for func in raw_functions:
        for cap in func['capabilities']:
            capabilities_count[cap] += 1

    if capabilities_count:
        print("\nDetected Capabilities:")
        for cap, count in sorted(capabilities_count.items(), key=lambda x: x[1], reverse=True):
            print(f"  {cap}: {count} functions")

    # API 사용 분포
    api_count = defaultdict(int)
    for func in raw_functions:
        for api in func['api_calls']:
            api_count[api] += 1

    if api_count:
        print("\nMost Used APIs (Top 10):")
        for api, count in sorted(api_count.items(), key=lambda x: x[1], reverse=True)[:10]:
            print(f"  {api}: {count} functions")

    print("=" * 100)


def print_analysis_summary(raw_functions: list) -> None:
    """분석 요약 출력"""
    print("\n[Analysis Summary] Rich Metadata Extraction")
    print("=" * 100)

    print(f"\nTotal Functions: {len(raw_functions)}")

    # 중요도별 상위 함수
    critical_funcs = sorted(
        [f for f in raw_functions if f['importance_level'] == 'critical'],
        key=lambda x: x['importance_score'],
        reverse=True
    )[:5]

    print("\nTop Critical Functions:")
    for func in critical_funcs:
        print(f"  {func['name']:20s} @ {func['entry']:10s} | Score: {func['importance_score']:3d} | "
              f"Complexity: {func['complexity']:3d} | XRefs: {func['xrefs_in']:3d}")

    # 높은 XREF를 가진 함수
    high_xref = sorted(
        raw_functions,
        key=lambda x: x['xrefs_in'],
        reverse=True
    )[:5]

    print("\nHighest XREF Functions:")
    for func in high_xref:
        print(f"  {func['name']:20s} @ {func['entry']:10s} | XRefs: {func['xrefs_in']:3d}")

    # 복잡한 함수
    complex_funcs = sorted(
        raw_functions,
        key=lambda x: x['complexity'],
        reverse=True
    )[:5]

    print("\nMost Complex Functions:")
    for func in complex_funcs:
        print(f"  {func['name']:20s} @ {func['entry']:10s} | Complexity: {func['complexity']:3d}")

    print("=" * 100)


def resolve_config(args: argparse.Namespace) -> tuple[Path, Path, Path, Path, str]:
    try:
        from dotenv import load_dotenv
    except ImportError as exc:
        raise RuntimeError(
            "python-dotenv is not installed. Run `pip install -r requirements.txt` and retry."
        ) from exc

    print("[resolve_config] Loading .env file...")
    load_dotenv()
    print("    ✓ Environment loaded")

    ghidra_home = args.ghidra_home or os.getenv("GHIDRA_HOME")
    binary_path = args.binary or os.getenv("TARGET_BINARY")
    output_path = args.output or os.getenv("OUTPUT_PATH") or "ghidra_functions.json"
    project_dir = args.project_dir or os.getenv("PROJECT_DIR") or ".ghidra_project"
    project_name = args.project_name or os.getenv("PROJECT_NAME") or "AutoProject"

    print(f"    ghidra_home: {ghidra_home}")
    print(f"    binary_path: {binary_path}")
    print(f"    output_path: {output_path}")
    print(f"    project_dir: {project_dir}")
    print(f"    project_name: {project_name}")

    missing = []
    if not ghidra_home:
        missing.append("GHIDRA_HOME or --ghidra-home")
    if not binary_path:
        missing.append("TARGET_BINARY or --binary")
    if missing:
        raise ValueError(f"Missing required settings: {', '.join(missing)}")

    ghidra_home_path = Path(ghidra_home).resolve()
    binary_file_path = Path(binary_path).resolve()
    output_file_path = Path(output_path).resolve()
    project_dir_path = Path(project_dir).resolve()

    if not ghidra_home_path.exists():
        raise FileNotFoundError(f"GHIDRA_HOME not found: {ghidra_home_path}")
    if not binary_file_path.is_file():
        raise FileNotFoundError(f"TARGET_BINARY not found: {binary_file_path}")

    if output_file_path.exists() and output_file_path.is_dir():
        output_file_path = output_file_path / "ghidra_functions.json"

    return (
        ghidra_home_path,
        binary_file_path,
        output_file_path,
        project_dir_path,
        project_name,
    )


def main() -> None:
    print("=" * 60)
    print("Starting GhidrAgent Analysis (Phase 2 - Semantic Enrichment)")
    print("=" * 60)

    print("\n[main] Parsing arguments...")
    args = parse_args()

    print("\n[main] Resolving configuration...")
    ghidra_home, binary_path, output_path, project_dir, project_name = resolve_config(args)

    print("\n[main] Running enriched Ghidra analysis...")
    raw_functions = run_analysis_and_export(
        ghidra_home=ghidra_home,
        binary_path=binary_path,
        output_path=output_path,
        project_dir=project_dir,
        project_name=project_name,
    )

    # 분석 결과 검증
    verify_functions(raw_functions)

    # 분석 요약
    print_analysis_summary(raw_functions)

    print("\n" + "=" * 60)
    print("Phase 2 Complete - Ready for LLM Analysis")
    print("=" * 60)


if __name__ == "__main__":
    main()