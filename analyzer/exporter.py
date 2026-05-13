import json

from pathlib import Path
from typing import List


def export_to_json(
        rows: List[dict],
        output_path: Path,
) -> None:

    if (
            output_path.exists()
            and output_path.is_dir()
    ):
        output_path = (
                output_path
                / "functions.json"
        )

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with output_path.open(
            "w",
            encoding="utf-8",
    ) as fp:

        json.dump(
            rows,
            fp,
            ensure_ascii=False,
            indent=2,
        )