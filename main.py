import argparse
import logging
import os

from pathlib import Path

from dotenv import load_dotenv

from analyzer.runtime import run_analysis
from analyzer.exporter import export_to_json


def configure_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(message)s",
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="GhidrAgent"
    )

    parser.add_argument(
        "--ghidra-home",
        help="Override GHIDRA_HOME",
    )

    parser.add_argument(
        "--binary",
        help="Override TARGET_BINARY",
    )

    parser.add_argument(
        "--output",
        help="Override OUTPUT_PATH",
    )

    parser.add_argument(
        "--project-dir",
        help="Override PROJECT_DIR",
    )

    parser.add_argument(
        "--project-name",
        help="Override PROJECT_NAME",
    )

    return parser.parse_args()


def load_config(
        args: argparse.Namespace,
) -> dict:

    load_dotenv()

    config = {
        "ghidra_home": (
                args.ghidra_home
                or os.getenv("GHIDRA_HOME")
        ),

        "binary": (
                args.binary
                or os.getenv("TARGET_BINARY")
        ),

        "output": (
                args.output
                or os.getenv(
            "OUTPUT_PATH",
            "output/functions.json",
        )
        ),

        "project_dir": (
                args.project_dir
                or os.getenv(
            "PROJECT_DIR",
            ".ghidra_projects",
        )
        ),

        "project_name": (
                args.project_name
                or os.getenv(
            "PROJECT_NAME",
            "GhidrAgentProject",
        )
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

    return config


def validate_paths(
        ghidra_home: Path,
        binary_path: Path,
) -> None:

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


def main() -> None:
    configure_logging()

    args = parse_args()

    config = load_config(args)

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

    validate_paths(
        ghidra_home,
        binary_path,
    )

    logging.info("Starting analysis")

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
        "Analysis complete (%d functions)",
        len(results),
    )


if __name__ == "__main__":
    main()