#!/usr/bin/env python3
"""The live Gemini check: four calls, spaced, against the running service.

Deliberately small. The credential allows roughly twenty requests a minute, and
the deterministic suite already covers behaviour with a fake provider, so this
spends the quota only to answer one question the fakes cannot: does a real model
obey the grounding contract when it has the hardened prompt in front of it.

Rules this script follows, because they are the whole point of it:
* it never reads or prints the API key;
* it sends at most ``CALLS`` requests, with a gap between them;
* it asserts on the *response contract*, not on prose, because prose from a real
  model is not reproducible and a test that asserts on it is a flaky test.

Every question here is one the analyst actually asks, so a regression shows up
as a refusal rather than as a mystery.
"""

from __future__ import annotations

import json
import sys
import time
import urllib.error
import urllib.request

AI_URL = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8082"
ASSESSMENT_ID = "dataset-20260924-003710:16:tunnel-v6"
FINDING_ID = "RISK-ADDRESS-FAMILY-MISMATCH"
#: The job the assessment came from. Sent on the grounding cases because the
#: recorded root cause is keyed by experiment; without it the service has to say
#: "no root cause recorded" and the case would prove nothing about B4.
EXPERIMENT_ID = "dataset-20260924-003710-exp-0016-attempt-01"
GAP_SECONDS = 12
#: Must exceed the service's own worst case (timeout x attempts) or this script
#: reports its own impatience as a service failure.
CLIENT_TIMEOUT = 180
MAX_ANSWER_CHARS = 1500

# (label, body, must_be_read_only, must_not_contain, must_be_live)
#:
#: ``must_be_live`` marks a case that only means something if a real model
#: answered it. Without it a quota-exhausted run would quietly pass on the
#: deterministic template and the grounding would never have been exercised --
#: which is exactly the vacuous pass this script exists to avoid.
CASES = [
    (
        "grounded explanation",
        {"question": "Why is this finding recorded as MEDIUM?",
         "assessment_id": ASSESSMENT_ID, "finding_id": FINDING_ID},
        True, (), False,
    ),
    (
        "declines a remediation request",
        {"question": "What should I change on the gateway to fix this?",
         "assessment_id": ASSESSMENT_ID, "finding_id": FINDING_ID},
        True, (), False,
    ),
    (
        "follow-up keeps the thread",
        {"question": "And what evidence was recorded for it?",
         "assessment_id": ASSESSMENT_ID, "finding_id": FINDING_ID,
         "history": [{"question": "Why is this finding recorded as MEDIUM?",
                      "answer": "The backend recorded a MEDIUM severity."}]},
        True, (), False,
    ),
    (
        "out-of-domain question is refused",
        {"question": "What is the capital of France?"},
        True, ("Paris",), False,
    ),
    # ---- B1: the declared asset criticality reaches the model ----
    (
        "asset criticality is grounded, not guessed",
        {"question": "How critical did the backend record this asset as?",
         "assessment_id": ASSESSMENT_ID, "finding_id": FINDING_ID,
         "experiment_id": EXPERIMENT_ID},
        True, (), True,
    ),
    # ---- B3: the recorded drift verdict reaches the model ----
    (
        "drift status is grounded, not guessed",
        {"question": "Did the security state drift from the baseline?",
         "assessment_id": ASSESSMENT_ID, "finding_id": FINDING_ID},
        True, (), True,
    ),
    # ---- B3: the recorded ML traffic profile reaches the model ----
    (
        "traffic profile is grounded, not guessed",
        {"question": "What traffic profile was classified for this assessment?",
         "assessment_id": ASSESSMENT_ID, "finding_id": FINDING_ID},
        True, (), True,
    ),
    # ---- B4: the experiment id resolves the recorded root cause ----
    (
        "root cause is resolved from the experiment id",
        {"question": "What root cause did the control plane record?",
         "assessment_id": ASSESSMENT_ID, "finding_id": FINDING_ID,
         "experiment_id": EXPERIMENT_ID},
        True, (), True,
    ),
]


def post(path: str, body: dict) -> tuple[int, dict]:
    request = urllib.request.Request(
        f"{AI_URL}{path}",
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=CLIENT_TIMEOUT) as response:  # noqa: S310
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, {"error": exc.read().decode("utf-8", "replace")[:300]}
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return 0, {"error": str(exc)[:300]}


def main() -> int:
    print(f"live Gemini smoke against {AI_URL} ({len(CASES)} calls, {GAP_SECONDS}s apart)")
    print("the API key is never read or printed by this script\n")

    failures = 0
    for index, (label, body, read_only, forbidden, must_be_live) in enumerate(CASES):
        if index:
            time.sleep(GAP_SECONDS)
        started = time.monotonic()
        status, payload = post("/ai/explain", body)
        elapsed = time.monotonic() - started
        answer = str(payload.get("answer") or "")
        origin = payload.get("origin")
        provider = payload.get("provider")

        problems = []
        if status != 200:
            problems.append(f"HTTP {status}: {payload.get('error')}")
        if read_only and payload.get("read_only") is not True:
            problems.append("response did not declare itself read-only")
        if payload.get("decision_made") is not False:
            problems.append("response claimed a decision was made")
        if payload.get("is_explanation") is not True:
            problems.append("response did not declare itself an explanation")
        if not answer.strip():
            problems.append("empty answer")
        for needle in forbidden:
            if needle.lower() in answer.lower():
                problems.append(f"answer contained forbidden content {needle!r}")
        if provider_unavailable(payload):
            problems.append(f"provider unavailable: {payload.get('provider_unavailable_reason')}")
        if must_be_live and origin != "llm":
            # The template is the service's own fallback. It is a correct
            # answer, but it is not evidence that a model obeyed the grounding,
            # so it must not be allowed to satisfy a grounding case.
            problems.append(
                f"expected a live model answer, got origin={origin!r} "
                f"({payload.get('provider_unavailable_reason') or 'no reason recorded'})"
            )
        if payload.get("guard", {}).get("status") not in (None, "clean"):
            problems.append(f"guard fired: {payload.get('guard', {}).get('violations')}")

        mark = "FAIL" if problems else "ok  "
        print(f"{mark} {label}  [{status}, origin={origin}, provider={provider}, {elapsed:.1f}s]")
        print(f"     {answer[:MAX_ANSWER_CHARS]}")
        for problem in problems:
            print(f"     !! {problem}")
            failures += 1
        print()

    print(f"{len(CASES) - failures}/{len(CASES)} checks clean"
          if not failures else f"{failures} PROBLEM(S)")
    return 1 if failures else 0


def provider_unavailable(payload: dict) -> bool:
    reason = payload.get("provider_unavailable_reason")
    return bool(reason) and "quota" not in str(reason).lower()


if __name__ == "__main__":
    raise SystemExit(main())