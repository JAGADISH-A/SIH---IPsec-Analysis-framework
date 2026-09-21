"""Materialization CLI (Phase 3).

Read-only expected-state materialization from SIH artifacts.

Usage::

    python -m correlation.tools.materialize_expected \
        --plan "D:\\sihipsec\\results\\datasets\\<run_id>\\staging\\plan.json" \
        --sequence 1

    python -m correlation.tools.materialize_expected \
        --plan <path> --batch --output out\\expected_states.jsonl

    python -m correlation.tools.materialize_expected \
        --campaign campaign-quality.json --sequence 1

The CLI never writes into ``D:\\sihipsec``; batch output lives under
``D:\\sihcolayer`` (or wherever ``--output`` points).
"""

import argparse
import json
import sys
from pathlib import Path

from ..adapters import (
    ExpectedStateAdapter,
    ExpectedStateMaterializationError,
    MaterializedExpectedState,
)
from ..version import CORRELATION_SCHEMA_VERSION

DEFAULT_BATCH_OUTPUT = Path(__file__).resolve().parents[2] / "out" / "expected_states.jsonl"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Materialize real expected testbed state from SIH artifacts "
                    "(Phase 3; read-only, no testbed execution)"
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--plan", help="path to results/datasets/<run_id>/staging/plan.json")
    source.add_argument("--campaign", help="path to a campaign-*.json file")
    source.add_argument("--config", help="path to an explicit configuration JSON")

    parser.add_argument("--sequence", type=int, default=1,
                        help="logical sequence (1-based) to materialize")
    parser.add_argument("--experiment-id",
                        help="exact experiment id (validated against the documented protocol)")
    parser.add_argument("--attempt", type=int, default=None,
                        help="physical attempt number (default 1)")
    parser.add_argument("--run-id", default=None,
                        help="dataset_run_id / run_id (inferred from the plan path when possible)")
    parser.add_argument("--batch", action="store_true",
                        help="materialize every valid plan sample (JSONL)")
    parser.add_argument("--output", default=None,
                        help="output file (single: JSON; batch: JSONL). Batch default: "
                             + str(DEFAULT_BATCH_OUTPUT))
    parser.add_argument("--duration", type=float, default=None,
                        help="explicit run-level traffic duration override")
    parser.add_argument("--port", type=int, default=None,
                        help="explicit run-level traffic port override")
    parser.add_argument("--capture-filter", default=None,
                        help="explicit run-level capture filter override")
    parser.add_argument("--materialized-at", default=None,
                        help="provenance timestamp (default: now; injectable for deterministic output)")
    return parser


def _materialize_single(adapter, args, config):
    if args.plan is not None:
        return adapter.from_plan(
            args.plan,
            args.sequence,
            experiment_id=args.experiment_id,
            attempt_number=args.attempt,
            run_id=args.run_id,
        )
    if args.campaign is not None:
        return adapter.from_campaign(
            args.campaign,
            args.sequence,
            experiment_id=args.experiment_id,
            attempt_number=args.attempt,
        )
    return adapter.from_config(
        config,
        run_id=args.run_id or "<unspecified>",
        sequence=args.sequence,
        experiment_id=args.experiment_id,
        attempt_number=args.attempt or 1,
        source_path=args.config,
    )


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    run_options = {
        "duration": args.duration,
        "port": args.port,
        "capture_filter": args.capture_filter,
    }
    run_options = {k: v for k, v in run_options.items() if v is not None}
    try:
        adapter = ExpectedStateAdapter(
            run_options=run_options or None,
            materialized_at=args.materialized_at,
        )
        if args.plan is not None and args.batch:
            states = adapter.materialize_all_plan_samples(
                args.plan, run_id=args.run_id
            )
            output = Path(args.output) if args.output else DEFAULT_BATCH_OUTPUT
            adapter.write_batch(states, output)
            print(
                f"batch materialized {len(states)} expected states -> {output}"
            )
            for state in states:
                print(
                    f"  seq={state.identity.sequence:>3} "
                    f"experiment={state.identity.experiment_id} "
                    f"mode={state.expected.mode} "
                    f"config_id={state.expected.configuration_id}"
                )
            return 0

        config = None
        if args.config is not None:
            config = json.loads(Path(args.config).read_text(encoding="utf-8"))
        state = _materialize_single(adapter, args, config)

        if args.output:
            Path(args.output).parent.mkdir(parents=True, exist_ok=True)
            Path(args.output).write_text(state.to_json() + "\n", encoding="utf-8")
            print(f"written -> {args.output}")
        else:
            print(state.to_json())
        return 0

    except ExpectedStateMaterializationError as exc:
        print(exc.describe(), file=sys.stderr)
        return 1
    except (ValueError, FileNotFoundError, json.JSONDecodeError) as exc:
        print(f"materialization failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())