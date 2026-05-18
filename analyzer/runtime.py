"""Ghidra 자동 분석 실행 - Pyhidra 최적화"""

import logging
from contextlib import contextmanager
from pathlib import Path
from typing import List

from analyzer.extractors.decompiler import create_decompiler, dispose_decompiler
from analyzer.extractors.function_data import extract_function_data

logger = logging.getLogger(__name__)


@contextmanager
def bundle_host_reference():
    """Keep Ghidra's script bundle host alive during headless analysis."""
    from ghidra.app.script import GhidraScriptUtil

    GhidraScriptUtil.acquireBundleHostReference()
    try:
        yield
    finally:
        GhidraScriptUtil.releaseBundleHostReference()


def initialize_pyhidra(ghidra_home: Path):
    """PyHidra 초기화"""
    from pyhidra.launcher import HeadlessPyhidraLauncher

    launcher = HeadlessPyhidraLauncher(
        verbose=False,
        install_dir=str(ghidra_home),
    )

    launcher.start()
    logger.info("Pyhidra initialized")


def open_or_create_project(
        project_dir: Path,
        project_name: str,
):
    """Ghidra 프로젝트 열기 또는 생성"""
    from ghidra.base.project import GhidraProject

    project_dir.mkdir(parents=True, exist_ok=True)
    project_path = project_dir / project_name
    marker_file = project_path / f"{project_name}.gpr"

    if marker_file.exists():
        logger.info("Opening existing project")
        project = GhidraProject.openProject(
            str(project_dir),
            project_name,
            True,
        )
    else:
        logger.info("Creating new project")
        project = GhidraProject.createProject(
            str(project_dir),
            project_name,
            False,
        )

    return project


def import_binary(project, binary_path: Path):
    """바이너리 파일 임포트"""
    from java.io import File

    logger.info("Importing binary")

    program = project.importProgram(File(str(binary_path)))

    if program is None:
        raise RuntimeError("Failed to import binary")

    logger.info("Binary imported")
    return program


def run_auto_analysis(program):
    """Ghidra 자동 분석 실행"""
    from ghidra.app.plugin.core.analysis import AutoAnalysisManager
    from ghidra.util.task import ConsoleTaskMonitor

    logger.info("Running auto analysis")

    try:
        analysis_manager = AutoAnalysisManager.getAnalysisManager(program)
        analysis_manager.initializeOptions()

        monitor = ConsoleTaskMonitor()
        analysis_manager.reAnalyzeAll(None)

        options = program.getOptions("Analysis")
        for option_name in options.getOptionNames():
            logger.info("Analysis option: %s", option_name)

        analysis_manager.startAnalysis(monitor)

        logger.info("Auto analysis completed")

    except Exception as e:
        # bundleHost NullPointerException 무시 (스크립팅 서브시스템)
        logger.warning(f"Auto analysis warning (non-critical): {e}")
        logger.info("Continuing with available analysis data")


def count_functions(program) -> int:
    """함수 개수 세기"""
    try:
        listing = program.getListing()
        funcs = listing.getFunctions(True)

        count = 0
        for _ in funcs:
            count += 1
        return count

    except Exception as e:
        logger.debug(f"Failed to count functions: {e}")
        return 0


def iterate_functions(program) -> List[dict]:
    """프로그램의 모든 함수 순회 및 데이터 추출"""
    from ghidra.program.flatapi import FlatProgramAPI

    flat_api = FlatProgramAPI(program)
    decompiler = create_decompiler(program)
    rows = []

    listing = program.getListing()
    funcs = listing.getFunctions(True)

    # 함수 개수 미리 계산 (진행 상황 표시용)
    total_functions = count_functions(program)
    logger.info(f"Found {total_functions} functions")

    # 함수 순회
    idx = 1
    skipped = 0

    try:
        for func in listing.getFunctions(True):
            func_name = func.getName()

            logger.info(
                "[%d/%d] Processing %s",
                idx,
                total_functions,
                func_name,
            )

            try:
                data = extract_function_data(flat_api, func, decompiler)

                # 함수 필터링으로 인해 None 반환된 경우 (thunk, CRT 등)
                if data is not None:
                    rows.append(data)
                else:
                    skipped += 1
                    logger.debug(f"Skipped function: {func_name}")

            except Exception:
                logger.exception(f"Failed processing {func_name}")
                skipped += 1
                continue

            finally:
                idx += 1
    finally:
        dispose_decompiler(decompiler)

    logger.info(
        "Analysis complete: %d functions analyzed, %d skipped",
        len(rows),
        skipped
    )

    return rows


def run_analysis(
        ghidra_home: Path,
        binary_path: Path,
        project_dir: Path,
        project_name: str,
) -> List[dict]:
    """바이너리 분석 실행 (메인 진입점)"""

    initialize_pyhidra(ghidra_home)

    project = open_or_create_project(project_dir, project_name)

    try:
        with bundle_host_reference():
            program = import_binary(project, binary_path)
            run_auto_analysis(program)
            rows = iterate_functions(program)

        return rows

    finally:
        try:
            logger.info("Closing project")
            project.close()
        except Exception:
            logger.exception("Project close failed")
