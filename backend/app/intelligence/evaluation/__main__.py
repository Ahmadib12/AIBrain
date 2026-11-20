import argparse
import asyncio
from pathlib import Path
import sys

from backend.app.intelligence.evaluation.cases import (
    DatasetSchemaError,
    load_dataset,
)
from backend.app.intelligence.evaluation.report import render_json_report
from backend.app.intelligence.evaluation.runner import (
    EvaluationExecutionError,
    run_evaluation,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the offline deterministic intelligence evaluation."
    )
    parser.add_argument(
        "--dataset",
        type=Path,
        help="Dataset JSON path (defaults to the Milestone 4A dataset).",
    )
    parser.add_argument(
        "--repeats",
        type=int,
        default=10,
        help="Measured runs per case (default: 10).",
    )
    parser.add_argument(
        "--warmup",
        type=int,
        default=2,
        help="Unmeasured warm-up runs per case (default: 2).",
    )
    return parser


async def _evaluate(args: argparse.Namespace) -> int:
    try:
        dataset = load_dataset(args.dataset)
    except DatasetSchemaError:
        print("Dataset loading or validation failed; details suppressed.", file=sys.stderr)
        return 2
    except Exception:
        print("Dataset loading failed; details suppressed.", file=sys.stderr)
        return 2
    try:
        result = await run_evaluation(
            dataset,
            repetitions=args.repeats,
            warmup_runs=args.warmup,
        )
    except EvaluationExecutionError as error:
        messages = {
            "request_construction": (
                "Evaluation request construction failed; details suppressed."
            ),
            "execution": "Evaluation execution failed; details suppressed.",
        }
        print(messages[error.category], file=sys.stderr)
        return 1
    except ValueError:
        print(
            "Invalid evaluation configuration; details suppressed.",
            file=sys.stderr,
        )
        return 2
    except Exception:
        print("Evaluation failed; details suppressed.", file=sys.stderr)
        return 1
    try:
        report = render_json_report(result)
    except Exception:
        print("Evaluation report generation failed; details suppressed.", file=sys.stderr)
        return 1
    print(report)
    return 0


def main() -> int:
    args = _parser().parse_args()
    try:
        return asyncio.run(_evaluate(args))
    except Exception:
        print("Evaluation failed; details suppressed.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
