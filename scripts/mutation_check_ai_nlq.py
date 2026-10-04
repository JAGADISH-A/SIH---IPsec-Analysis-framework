#!/usr/bin/env python3
"""Mutation check for the Gemini NLQ grounding changes.

A test that cannot fail is not a test. Each mutant below is a single, plausible
regression -- the kind that gets written by someone in a hurry -- applied to the
real source. A mutant that survives means the suite would have shipped the
defect silently, so this exits non-zero if any mutant survives.

Every mutant is reverted in a ``finally``, including on failure, so the working
tree is left exactly as it was found.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# (label, file, find, replace, tests that must fail)
MUTANTS = [
    (
        "gemini-drops-hardened-prompt",
        "correlation/ai/gemini.py",
        "SYSTEM_INSTRUCTION = SYSTEM_PROMPT + GEMINI_CONTEXT_APPENDIX",
        'SYSTEM_INSTRUCTION = "You are a helpful assistant."',
        "tests/test_ai_nlq_grounding.py::TestGeminiSendsTheHardenedPrompt",
    ),
    (
        "asset-hardcoded-to-none",
        "correlation/ai/context.py",
        "        asset=_asset(source, assessment_id, finding.finding_id),",
        "        asset=None,",
        "tests/test_ai_nlq_grounding.py::TestAssetCriticalityReachesTheModel",
    ),
    (
        # The original B1 defect, kept as a permanent regression mutant: the
        # suite once proved nothing because it read criticality from a flat
        # shape the store never produces, so every assertion passed vacuously.
        "asset-criticality-read-from-a-flat-shape",
        "correlation/ai/gemini_context.py",
        '    profile = asset.get("profile") if isinstance(asset.get("profile"), dict) else {}',
        '    profile = {"criticality": asset.get("criticality")}',
        "tests/test_ai_gemini.py::TestWhitelistedVerdictsArriveIntact",
    ),
    (
        "undeclared-asset-reads-as-low",
        "correlation/ai/context.py",
        "    if not asset or not asset.get(\"asset_id\"):\n        return None",
        "    if not asset:\n        asset = {\"asset_id\": \"gw-a\", \"configured\": True,"
        " \"profile\": {\"criticality\": \"low\"}}",
        "tests/test_ai_nlq_grounding.py::TestAssetCriticalityReachesTheModel",
    ),
    (
        "history-console-spelling-dropped",
        "correlation/ai/service.py",
        '        for role, own_key, _shared_key in _HISTORY_TURN_KEYS:\n'
        "            text = turn.get(own_key)",
        "        for role, own_key, _shared_key in ():\n"
        "            text = turn.get(own_key)",
        "tests/test_ai_nlq_grounding.py::TestConversationHistoryReachesTheModel",
    ),
    (
        "scope-ignores-record-references",
        "correlation/ai/scope.py",
        "        # widens scope when no assessment is selected.\n        or context_hits",
        "        # widens scope when no assessment is selected.",
        "tests/test_ai_nlq_grounding.py::TestScopeCoversTheQuestionsTheGroundingCanAnswer",
    ),
    (
        "scope-widens-without-a-selection",
        "correlation/ai/scope.py",
        "    context_hits = _find_terms(text, _CONTEXT_REFERENCE_TERMS) if has_context else ()",
        "    context_hits = _find_terms(text, _CONTEXT_REFERENCE_TERMS)",
        "tests/test_ai_nlq_grounding.py::TestScopeCoversTheQuestionsTheGroundingCanAnswer",
    ),
    (
        "limiter-off-by-one",
        "correlation/ai/quota.py",
        "            if len(self._stamps) >= self._limit:",
        "            if len(self._stamps) > self._limit:",
        "tests/test_ai_nlq_grounding.py::TestQuotaIsRespectedUnderBurst",
    ),
    (
        "cache-ignores-expiry",
        "correlation/ai/quota.py",
        "            if self._clock() - stored_at > self._ttl:",
        "            if False:",
        "tests/test_ai_nlq_grounding.py::TestQuotaIsRespectedUnderBurst",
    ),
    (
        "cache-disabled-entirely",
        "correlation/ai/quota.py",
        "        cached = self._cache.get(key)\n        if cached is not None:\n"
        "            self.served_from_cache += 1\n            return cached",
        "        cached = None",
        "tests/test_ai_nlq_grounding.py::TestQuotaIsRespectedUnderBurst",
    ),
    (
        "root-cause-invented-when-absent",
        "correlation/ai/context.py",
        "        root_cause = payload.get(\"root_cause\")\n"
        "        if not isinstance(root_cause, str) or not root_cause.strip():\n"
        "            return None",
        "        root_cause = payload.get(\"root_cause\") or \"UNKNOWN_FAILURE\"",
        "tests/test_ai_nlq_grounding.py::TestRootCauseIsRecordedOrDeclaredAbsent",
    ),
    (
        "root-cause-called-without-configured-control-plane",
        "correlation/ai/context.py",
        "        if not self._control or not experiment_id:\n            return None",
        "        if not experiment_id:\n            return None",
        "tests/test_ai_nlq_grounding.py::TestRootCauseIsRecordedOrDeclaredAbsent",
    ),
    (
        "throttle-becomes-an-error-not-a-fallback",
        "correlation/ai/quota.py",
        "            self.throttled += 1\n            raise ProviderError(THROTTLED_REASON)",
        "            self.throttled += 1\n            return self._inner.complete(messages)",
        "tests/test_ai_nlq_grounding.py::TestQuotaIsRespectedUnderBurst",
    ),
    (
        "request-rejects-declared-fields",
        "correlation/ai/service.py",
        'known = {"question", "assessment_id", "finding_id", "experiment_id", "history"}',
        'known = {"question", "assessment_id", "finding_id", "history"}',
        "tests/test_ai_nlq_grounding.py::TestRequestContract",
    ),
    # ---- B3: the two blocks the assistant now restates ----
    (
        # The whitelist and the payload are asserted against each other, so a
        # key that is documented but not built (or built but not documented) is
        # a silent boundary change.
        "whitelist-drifts-from-advertised-keys",
        "correlation/ai/gemini_context.py",
        '        "drift",\n        "traffic_profile",\n    ]',
        '    ]',
        "tests/test_ai_nlq_grounding.py::TestGroundingNeverOverridesTheBackend",
    ),
    (
        "drift-status-flattened-to-a-default",
        "correlation/ai/gemini_context.py",
        '        "configured": drift.configured,\n        "status": _text(drift.status, 32),',
        '        "configured": True,\n        "status": "no_drift",',
        "tests/test_ai_nlq_grounding.py::TestDriftStatusReachesTheModel",
    ),
    (
        "unconfigured-drift-reports-an-empty-changed-list",
        "correlation/ai/gemini_context.py",
        '    if drift.configured:\n        block["changed_variables"] = _bounded(',
        '    if drift.changed_variables is not None:\n        block["changed_variables"] = _bounded(',
        "tests/test_ai_nlq_grounding.py::TestDriftStatusReachesTheModel",
    ),
    (
        "traffic-profile-block-dropped",
        "correlation/ai/gemini_context.py",
        '        "recorded_comparisons",\n        "asset",\n        "root_cause",\n'
        '        "drift",\n        "traffic_profile",\n    ]',
        '        "recorded_comparisons",\n        "asset",\n        "root_cause",\n'
        '        "drift",\n    ]',
        "tests/test_ai_nlq_grounding.py::TestTrafficProfileReachesTheModel",
    ),
    (
        "traffic-class-dropped-but-confidence-kept",
        "correlation/ai/gemini_context.py",
        '        "traffic_class": _text(ml.traffic_class, 32),',
        '        "traffic_class": None,',
        "tests/test_ai_nlq_grounding.py::TestTrafficProfileReachesTheModel",
    ),
    # ---- F: the guard must refuse a contradicted verdict ----
    (
        "guard-stops-checking-contradicted-verdicts",
        "correlation/ai/guard.py",
        "        bad_verdicts = self._bad_verdicts(body)\n        if bad_verdicts:",
        "        bad_verdicts = set()\n        if bad_verdicts:",
        "tests/test_ai_nlq_grounding.py::TestGeminiCannotContradictSentinel",
    ),
    (
        "guard-treats-any-criticality-as-a-severity-again",
        "correlation/ai/guard.py",
        "                if _inside(match.span(), scoped):\n                    continue",
        "                if False:\n                    continue",
        "tests/test_ai_nlq_grounding.py::TestGeminiCannotContradictSentinel",
    ),
    # ---- B4: the experiment id must survive the hop ----
    (
        # The parsed id reaches the parse tests but never the engine, so the
        # assistant reports "no root cause recorded" for an assessment that has
        # one. Parsing it correctly is not the same as using it.
        "experiment-id-parsed-then-dropped-before-the-engine",
        "correlation/ai/service.py",
        "        finding_id=finding_id,\n        experiment_id=experiment_id,",
        "        finding_id=finding_id,\n        experiment_id=None,",
        "tests/test_ai_nlq_grounding.py::TestExperimentIdReachesTheEngine",
    ),
    (
        "experiment-id-guessed-when-absent",
        "correlation/ai/service.py",
        "        finding_id=finding_id,\n        experiment_id=experiment_id,",
        "        finding_id=finding_id,\n        experiment_id=experiment_id or \"exp-invented\",",
        "tests/test_ai_nlq_grounding.py::TestExperimentIdReachesTheEngine",
    ),
]


def _run(tests: str) -> tuple[int, str]:
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", tests, "-q", "-p", "no:cacheprovider"],
        cwd=ROOT, capture_output=True, text=True,
    )
    return proc.returncode, proc.stdout[-3000:] + proc.stderr[-1000:]


def main() -> int:
    survivors = []
    print(f"mutation check: {len(MUTANTS)} mutants\n")
    for label, rel, find, replace, tests in MUTANTS:
        path = ROOT / rel
        original = path.read_text()
        if find not in original:
            print(f"  SKIP  {label}: anchor not found in {rel}")
            survivors.append(f"{label} (anchor missing -- the mutant is not being tested)")
            continue
        try:
            path.write_text(original.replace(find, replace, 1))
            code, out = _run(tests)
            # A non-zero exit alone is not proof: a bad pytest flag or a
            # collection error also exits non-zero, and counting that as a kill
            # would report every mutant as caught while testing nothing. Require
            # an actual reported test failure.
            failed = [ln for ln in out.splitlines()
                      if ln.startswith("FAILED") or ln.startswith("SUBFAILED")]
            if "error" in out.lower() and not failed:
                print(f"  ERROR {label}: the run itself did not execute")
                print("        " + out.strip().splitlines()[-1][:160])
                survivors.append(f"{label} (harness error)")
            elif not failed:
                print(f"  ALIVE {label}")
                survivors.append(label)
            else:
                print(f"  killed {label} ({len(failed)} failing)")
        finally:
            path.write_text(original)

    print()
    if survivors:
        print(f"SURVIVORS ({len(survivors)}):")
        for name in survivors:
            print(f"  - {name}")
        return 1
    print(f"all {len(MUTANTS)} mutants killed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())