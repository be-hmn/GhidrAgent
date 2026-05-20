"""Score benchmark result JSON files."""

import argparse
import json
from pathlib import Path


RESULT_SCORES = {
    "correct": 1.0,
    "partial": 0.5,
    "wrong": 0.0,
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Score GhidrAgent benchmark results."
    )
    parser.add_argument(
        "benchmark",
        nargs="?",
        default="benchmarks/reversing_kr_baseline.json",
        help="Path to benchmark JSON.",
    )
    return parser.parse_args()


def load_benchmark(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as fp:
        return json.load(fp)


def score_cases(cases: list[dict]) -> dict:
    total = len(cases)
    counts = {
        "correct": 0,
        "partial": 0,
        "wrong": 0,
    }
    score = 0.0

    for case in cases:
        result = case.get("result", "wrong")
        case_score = case.get("score")

        if case_score is None:
            case_score = RESULT_SCORES.get(result, 0.0)

        if result in counts:
            counts[result] += 1
        score += float(case_score)

    return {
        "total_cases": total,
        "correct": counts["correct"],
        "partial": counts["partial"],
        "wrong": counts["wrong"],
        "score": score,
        "max_score": float(total),
        "accuracy": score / total if total else 0.0,
    }


def main() -> None:
    args = parse_args()
    path = Path(args.benchmark)
    benchmark = load_benchmark(path)
    summary = score_cases(benchmark.get("cases", []))

    print(f"Benchmark: {benchmark.get('benchmark', path.stem)}")
    print(f"Cases: {summary['total_cases']}")
    print(f"Correct: {summary['correct']}")
    print(f"Partial: {summary['partial']}")
    print(f"Wrong: {summary['wrong']}")
    print(f"Score: {summary['score']:.1f}/{summary['max_score']:.1f}")
    print(f"Accuracy: {summary['accuracy']:.2%}")


if __name__ == "__main__":
    main()
