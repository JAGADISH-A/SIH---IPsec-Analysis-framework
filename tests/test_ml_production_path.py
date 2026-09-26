"""Which RF -> correlation path is production, and which is not (finding #3).

The architecture audit reported that ``correlation/ml/controller_bridge.py`` and
``correlation/streaming/pipeline.py`` had zero non-test importers.  That wording
is stale for the bridge and is still true for the streaming pipeline, but the
stale wording hid the real question: which of the two is the production RF path
*by design*?

Static import evidence (this module re-derives it with AST, not by grep):

* ``correlation.ml.live_correlation`` is the production RF stage.  It is a
  ``python -m`` entry point, so a static importer scan necessarily reports no
  in-process importer for it; its reachability is proven by running the stage,
  not by counting imports.
* ``correlation.ml.controller_bridge`` sits on that stage: the production run
  calls ``infer_controller_ml_result`` once per live window, and the committed
  ``traffic_rf_v1`` Random Forest reaches ``correlation.models.MLResult``
  through it.
* ``correlation.streaming.pipeline`` is the earlier Phase 10 streaming
  architecture.  It cannot carry the real Random Forest at all
  (``correlation.ml.model_metadata.SUPPORTED_MODEL_TYPES`` is
  ``("nearest_centroid",)`` and the RF artifact is a joblib dict with no
  ``metadata``/``predict`` surface), its only window builder is a labelled test
  double, its ``ObservedStateBuilder`` is a duplicate of the authoritative
  ``ebpf.ipsec_state_builder`` that defaults to documentation endpoints, and its
  only transport is in-memory.  Wiring it into production would add a second,
  Random-Forest-blind ML path, so it stays an alternate architecture.

These tests exist to keep that conclusion honest in both directions: the
production path must keep reaching the bridge, and the streaming layer must not
silently acquire a production ML role.  No test here imports anything to create
an importer; every assertion is about code that already exists.
"""

from __future__ import annotations

import ast
import json
import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

PLAN_PATH = "results/datasets/acc-eng-02/staging/plan.json"
LIVE_EVENTS = "results/observed-state/live_events_full.jsonl"
MODEL_PATH = "results/ml/model_traffic_rf_v1.joblib"

SEAM_MODULE = "correlation.ml.live_correlation"
BRIDGE_MODULE = "correlation.ml.controller_bridge"
PIPELINE_MODULE = "correlation.streaming.pipeline"
STREAMING_PACKAGE = "correlation.streaming"

#: Directories that never count as production callers.
NON_PRODUCTION_PREFIXES = ("tests", "test_", "conftest")


def _module_name(path: Path) -> str:
    rel = path.relative_to(REPO_ROOT).with_suffix("")
    parts = list(rel.parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _repo_modules():
    """Every non-test Python module in the repository, as (name, path)."""
    skip = {".git", ".venv", "results", "out", "node_modules", "__pycache__", ".pytest_cache"}
    for path in sorted(REPO_ROOT.rglob("*.py")):
        if any(part in skip for part in path.relative_to(REPO_ROOT).parts):
            continue
        yield _module_name(path), path


def _is_test_module(name: str) -> bool:
    head = name.split(".")[0]
    return head in ("tests", "conftest") or head.startswith("test_")


def _direct_imports(path: Path) -> set:
    """Modules imported by ``path`` (relative imports resolved absolutely)."""
    tree = ast.parse(path.read_text(encoding="utf-8"), str(path))
    package = _module_name(path).rsplit(".", 1)[0] if path.name != "__init__.py" else _module_name(path)
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                found.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                base = package.split(".")
                base = base[: len(base) - (node.level - 1)] if node.level > 1 else base
                target = ".".join(base + ([node.module] if node.module else []))
            else:
                target = node.module or ""
            if target:
                found.add(target)
    return found


def _importers(target: str):
    """(production_importers, test_importers) for ``target``."""
    production, tests = set(), set()
    for name, path in _repo_modules():
        try:
            imports = _direct_imports(path)
        except SyntaxError:  # pragma: no cover - defensive
            continue
        if not any(i == target or i.startswith(target + ".") for i in imports):
            continue
        (tests if _is_test_module(name) else production).add(name)
    return production, tests


def _import_closure(entry: str) -> set:
    """Transitive import closure of ``entry`` restricted to repo modules."""
    known = dict(_repo_modules())
    seen, pending = set(), [entry]
    while pending:
        current = pending.pop()
        if current in seen or current not in known:
            continue
        seen.add(current)
        for imported in _direct_imports(known[current]):
            if imported not in seen:
                pending.append(imported)
    return seen


class TestControllerBridgeIsOnTheProductionPath(unittest.TestCase):
    """controller_bridge is reached by a real production stage, not only tests."""

    def test_bridge_has_a_non_test_production_importer(self):
        production, tests = _importers(BRIDGE_MODULE)

        self.assertIn(SEAM_MODULE, production)
        self.assertTrue(tests, "sanity: the bridge is exercised by tests too")

    def test_every_production_importer_is_a_known_consumer(self):
        production, _ = _importers(BRIDGE_MODULE)

        self.assertEqual(
            {SEAM_MODULE, "correlation.artifacts"},
            production,
            "a new production importer of the bridge appeared; the RF->MLResult "
            "boundary must stay single-sourced through the live-correlation seam "
            "and the recorded-artifact store, not a parallel path",
        )

    def test_production_seam_reaches_the_bridge_and_never_the_streaming_layer(self):
        closure = _import_closure(SEAM_MODULE)

        self.assertIn(BRIDGE_MODULE, closure)
        streaming = sorted(m for m in closure if m.startswith(STREAMING_PACKAGE))
        self.assertEqual([], streaming)

    def test_production_seam_is_a_runnable_stage_not_just_a_library(self):
        source = (REPO_ROOT / "correlation/ml/live_correlation.py").read_text()

        self.assertIn('if __name__ == "__main__":', source)
        self.assertIn("def main(", source)


class TestStreamingPipelineIsAnAlternateArchitecture(unittest.TestCase):
    """streaming/pipeline.py is the earlier Phase 10 layer, not the RF path."""

    def test_pipeline_has_no_production_importer_outside_its_own_package(self):
        production, _ = _importers(PIPELINE_MODULE)

        self.assertEqual(
            {STREAMING_PACKAGE},
            production,
            "streaming.pipeline gained a production importer: if it is now on the "
            "live path the architecture must be re-audited before it is wired",
        )

    def test_streaming_ml_provider_cannot_accept_the_committed_random_forest(self):
        import joblib

        from correlation.streaming.ml_provider import MODE_REAL_MODEL, MLInferenceProvider

        artifact = joblib.load(REPO_ROOT / MODEL_PATH)
        with self.assertRaises(Exception) as caught:
            MLInferenceProvider(model=artifact, mode=MODE_REAL_MODEL)

        self.assertIn("metadata", str(caught.exception))

    def test_correlation_model_metadata_contract_excludes_random_forest(self):
        from correlation.ml import model_metadata

        self.assertEqual(
            (model_metadata.MODEL_TYPE_CENTROID,),
            model_metadata.SUPPORTED_MODEL_TYPES,
            "nearest-centroid is the only correlation-side model contract; the "
            "RandomForest crosses the boundary through controller_bridge instead",
        )

    def test_streaming_window_builder_is_only_a_labelled_test_double(self):
        from correlation.streaming.ml_provider import TestDoubleWindowBuilder

        self.assertEqual("TEST_DOUBLE", TestDoubleWindowBuilder().label)

    def test_streaming_observed_builder_is_not_the_authoritative_state_engine(self):
        from correlation.streaming.pipeline import ObservedStateBuilder

        endpoints = ObservedStateBuilder().endpoints

        self.assertEqual({"a": "192.0.2.1", "b": "192.0.2.2"}, endpoints)
        self.assertIn("ebpf.ipsec_state_builder", _import_closure(SEAM_MODULE))

    def test_streaming_layer_has_no_production_transport(self):
        from correlation.streaming.producer import EventProducer, MemoryTransport

        source = (REPO_ROOT / "correlation/streaming/producer.py").read_text()

        self.assertIn("MemoryTransport", source)
        self.assertNotIn("confluent_kafka", source)
        self.assertIs(MemoryTransport, type(EventProducer().transport))


class TestProductionRunCarriesTheRealRf(unittest.TestCase):
    """Runtime proof: the real committed RF runs; streaming stays unloaded."""

    _cached: dict = {}

    def _run_probe(self):
        if self._cached:
            return self._cached["facts"], self._cached["payload"]
        events = (REPO_ROOT / LIVE_EVENTS).read_text(encoding="utf-8").splitlines()[:30]
        events_path = Path(self.enterContext(_temp_dir())) / "events.jsonl"
        events_path.write_text("\n".join(events) + "\n", encoding="utf-8")
        out_path = events_path.parent / "out.json"
        argv = [
            "live_correlation",
            "--events", str(events_path),
            "--plan", str(REPO_ROOT / PLAN_PATH),
            "--sequence", "1",
            "--model", str(REPO_ROOT / MODEL_PATH),
            "--endpoints", "a=192.168.100.1,b=192.168.100.2",
            "--output", str(out_path),
        ]
        probe = (
            "import runpy, sys\n"
            # Tripwire: the Phase-5 nearest-centroid pipeline must never run on
            # the RF production path.  If it is invoked the stage fails loudly.
            "import correlation.ml.inference as _nearest\n"
            "_nc_original = _nearest.MLInferencePipeline.run\n"
            "def _tripwire(*a, **k):\n"
            "    raise RuntimeError('nearest-centroid run() was invoked')\n"
            "_nearest.MLInferencePipeline.run = _tripwire\n"
            f"sys.argv = {argv!r}\n"
            "code = 0\n"
            "try:\n"
            "    runpy.run_module('correlation.ml.live_correlation', "
            "run_name='__main__', alter_sys=True)\n"
            "except SystemExit as exc:\n"
            "    code = exc.code or 0\n"
            "loaded = sorted(m for m in sys.modules if m.startswith('correlation.streaming'))\n"
            "print('PROBE_RC', code)\n"
            "print('PROBE_STREAMING', loaded)\n"
            "print('PROBE_NC_PATCHED', "
            "_nearest.MLInferencePipeline.run is not _nc_original)\n"
            "print('PROBE_BRIDGE', 'correlation.ml.controller_bridge' in sys.modules)\n"
        )
        completed = subprocess.run(
            [sys.executable, "-c", probe],
            cwd=REPO_ROOT, capture_output=True, text=True,
        )
        self.assertEqual(0, completed.returncode, completed.stderr)
        facts = {}
        for line in completed.stdout.splitlines():
            if line.startswith("PROBE_"):
                key, _, value = line.partition(" ")
                facts[key] = value
        payload = json.loads(out_path.read_text(encoding="utf-8"))
        TestProductionRunCarriesTheRealRf._cached = {"facts": facts, "payload": payload}
        return facts, payload

    def test_production_stage_runs_the_committed_random_forest(self):
        facts, payload = self._run_probe()

        self.assertEqual("0", facts["PROBE_RC"])
        self.assertTrue(payload["passive_only"])
        self.assertEqual("materialized_plan", payload["expected_source"])
        self.assertGreater(payload["window_count"], 0)
        first = payload["windows"][0]
        self.assertEqual("traffic_rf_v1", first["ml_result"]["model_version"])
        self.assertIsNone(first["ml_result"]["anomaly"])
        self.assertEqual("controller", first["ml_result"]["extras"]["bridge"])

    def test_production_stage_never_loads_the_streaming_layer(self):
        facts, _ = self._run_probe()

        self.assertEqual("True", facts["PROBE_BRIDGE"])
        self.assertEqual("[]", facts["PROBE_STREAMING"])

    def test_production_stage_never_invokes_the_nearest_centroid_pipeline(self):
        """The RF stage must not reach ``MLInferencePipeline.run`` at all."""
        facts, payload = self._run_probe()

        self.assertEqual("True", facts["PROBE_NC_PATCHED"], "tripwire not installed")
        # rc 0 with the tripwire armed proves no call happened: a call would
        # have raised and surfaced as a non-zero exit.
        self.assertEqual("0", facts["PROBE_RC"])
        self.assertGreater(payload["window_count"], 0)
        for window in payload["windows"]:
            extras = window["ml_result"]["extras"]
            self.assertEqual("traffic_rf_v1", extras["model_version"])
            self.assertNotIn("nearest_centroid", str(extras["model_version"]))


def _temp_dir():
    import contextlib
    import tempfile

    @contextlib.contextmanager
    def _cm():
        with tempfile.TemporaryDirectory() as name:
            yield name

    return _cm()


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
