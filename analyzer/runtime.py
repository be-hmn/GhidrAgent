# analyzer/runtime.py

import logging

from pathlib import Path
from typing import List

from analyzer.extractors.function_data import (
    extract_function_data,
)

logger = logging.getLogger(__name__)


def initialize_pyhidra(
        ghidra_home: Path,
):

    from pyhidra.launcher import (
        HeadlessPyhidraLauncher,
    )

    launcher = HeadlessPyhidraLauncher(
        verbose=False,
        install_dir=str(ghidra_home),
    )

    launcher.start()

    logger.info(
        "Pyhidra initialized"
    )


def open_or_create_project(
        project_dir: Path,
        project_name: str,
):

    from ghidra.base.project import (
        GhidraProject,
    )

    project_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    project_path = (
            project_dir / project_name
    )

    marker_file = (
            project_path /
            f"{project_name}.gpr"
    )

    if marker_file.exists():

        logger.info(
            "Opening existing project"
        )

        project = (
            GhidraProject.openProject(
                str(project_dir),
                project_name,
                True,
            )
        )

    else:

        logger.info(
            "Creating new project"
        )

        project = (
            GhidraProject.createProject(
                str(project_dir),
                project_name,
                False,
            )
        )

    return project


def import_binary(
        project,
        binary_path: Path,
):

    from java.io import File

    logger.info(
        "Importing binary"
    )

    program = project.importProgram(
        File(str(binary_path))
    )

    if program is None:

        raise RuntimeError(
            "Failed to import binary"
        )

    logger.info(
        "Binary imported"
    )

    return program


def run_auto_analysis(
        program,
):

    from ghidra.app.plugin.core.analysis import (
        AutoAnalysisManager,
    )

    from ghidra.util.task import (
        ConsoleTaskMonitor,
    )

    logger.info(
        "Running auto analysis"
    )

    analysis_manager = (
        AutoAnalysisManager
        .getAnalysisManager(
            program
        )
    )

    analysis_manager.initializeOptions()

    monitor = ConsoleTaskMonitor()

    analysis_manager.reAnalyzeAll(
        None
    )

    analysis_manager.startAnalysis(
        monitor
    )

    logger.info(
        "Auto analysis completed"
    )


def iterate_functions(
        program,
) -> List[dict]:

    from ghidra.program.flatapi import (
        FlatProgramAPI,
    )

    flat_api = FlatProgramAPI(
        program
    )

    rows = []

    listing = (
        program.getListing()
    )

    funcs = listing.getFunctions(
        True
    )

    for idx, func in enumerate(funcs):

        func_name = func.getName()

        logger.info(
            "[%d] Processing %s",
            idx + 1,
            func_name,
            )

        try:

            data = extract_function_data(
                flat_api,
                func,
            )

            rows.append(
                data
            )

        except Exception:

            logger.exception(
                "Failed processing %s",
                func_name,
            )

            continue

    return rows


def run_analysis(
        ghidra_home: Path,
        binary_path: Path,
        project_dir: Path,
        project_name: str,
) -> List[dict]:

    initialize_pyhidra(
        ghidra_home
    )

    project = open_or_create_project(
        project_dir,
        project_name,
    )

    try:

        program = import_binary(
            project,
            binary_path,
        )

        run_auto_analysis(
            program
        )

        rows = iterate_functions(
            program
        )

        logger.info(
            "Analysis complete"
        )

        return rows

    finally:

        try:

            logger.info(
                "Closing project"
            )

            project.close()

        except Exception:

            logger.exception(
                "Project close failed"
            )