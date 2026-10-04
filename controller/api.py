from pathlib import Path
from threading import Lock, Thread
from uuid import uuid4

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, model_validator

from .dataset_api import (
    DEFAULT_MAX_TARGET_SAMPLES,
    create_dataset_router,
)
from . import diagnose
from .executor import run_experiment
from .testbed_lock import EXPERIMENT, TESTBED_LOCK
from .topology import resolve_topology
from .traffic import (
    PROFILES,
    DEFAULT_DURATION,
    DURATION_RANGE,
)

FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"

app = FastAPI(
    title="IPsec Testbed API",
    description="API for running configurable IPsec VPN experiments",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")

# Dataset Run API (Module 6): user-controlled sample count on the SAME
# FastAPI app.  It shares the single testbed reservation registry with the
# manual experiment endpoints so the two can never run concurrently.
app.include_router(
    create_dataset_router(
        results_root="results",
        max_target_samples=DEFAULT_MAX_TARGET_SAMPLES,
        lock=TESTBED_LOCK,
    )
)


class IKEConfig(BaseModel):
    version: int = 2
    encryption: str
    integrity: str
    dh_group: str


class ESPConfig(BaseModel):
    encryption: str
    integrity: str | None = None
    dh_group: str
    pfs: bool


class TrafficConfig(BaseModel):
    profile: str
    duration: int = DEFAULT_DURATION


class ExperimentConfig(BaseModel):
    mode: str
    address_family: str = "ipv4"
    nat: bool = False
    ike: IKEConfig
    esp: ESPConfig
    traffic: TrafficConfig | None = None

    @model_validator(mode="after")
    def _reject_unsupported_nat(self):
        """Fail a request for a NAT deployment that does not exist.

        ``nat`` used to be absent from this model. Pydantic drops unknown
        fields, so ``nat: true`` never reached ``model_dump()``, the executor
        always saw ``nat=False``, and a request for NAT-T silently deployed
        the NON-NAT lab and reported PASS. Worse, an unsupported combination
        such as IPv6 NAT-T was downgraded instead of refused.

        The supported-NAT decision is NOT re-implemented here: ``resolve_topology``
        is the executor's own gate, so the API accepts exactly what the executor
        can run and surfaces the executor's own message verbatim. The executor's
        rejection logic is untouched and still runs again inside the executor.

        The check is skipped entirely when ``nat`` is false, so existing
        non-NAT requests keep behaving exactly as before.
        """
        if self.nat:
            try:
                resolve_topology(self.mode, self.address_family, nat=True)
            except ValueError as exc:
                raise ValueError(str(exc)) from exc
        return self


jobs = {}
jobs_lock = Lock()
active_job_id = None


@app.get("/", include_in_schema=False)
def root():
    return FileResponse(FRONTEND_DIR / "index.html")


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/experiments/configurations")
def get_configurations():
    return {
        "modes": ["tunnel", "transport"],
        "address_families": ["ipv4", "ipv6"],
        "ike": {
            "version": 2,
            "encryption": ["aes128", "aes256"],
            "integrity": ["sha256", "sha384", "sha512"],
            "dh_groups": ["modp2048", "modp3072", "modp4096"],
        },
       "esp": {
            "encryption": ["aes128gcm16", "aes256gcm16", "aes128cbc", "aes256cbc"],
            "integrity": ["sha256", "sha384", "sha512"],
            "dh_groups": ["modp2048", "modp3072", "modp4096"],
            "pfs": [True, False],
        },
        "traffic": {
            "profiles": sorted(PROFILES),
            "duration": {
                "min": DURATION_RANGE[0],
                "max": DURATION_RANGE[1],
                "default": DEFAULT_DURATION,
            },
        },
    }


PIPELINE_STAGES = ("DEPLOY", "IPSEC", "OBSERVATION", "CONNECTIVITY", "TRAFFIC")


def _data_plane_classification(result):
    """Return the classifier verdict a non-raising ``FAIL`` result already holds.

    ``run_experiment`` reports a data-plane failure by returning (not raising),
    so the classification lives under ``result["connectivity"]``. Returns
    ``None`` for a passing run, or one without a classification, leaving those
    jobs exactly as they were.
    """
    if not isinstance(result, dict):
        return None

    if result.get("status") != "FAIL":
        return None

    connectivity = result.get("connectivity")
    if not isinstance(connectivity, dict):
        return None

    classification = connectivity.get("classification")
    if not isinstance(classification, dict):
        return None

    if classification.get("root_cause") is None:
        return None

    return classification


def execute_job(job_id, config):
    global active_job_id

    with jobs_lock:
        jobs[job_id]["status"] = "RUNNING"
        jobs[job_id]["stage"] = "RUNNING"

    def report_stage(stage):
        with jobs_lock:
            jobs[job_id]["stage"] = stage

    try:
        result = run_experiment(config, on_stage=report_stage, job_id=job_id)

        # A data-plane failure does not raise: ``run_experiment`` returns a
        # result whose ``status`` is ``FAIL`` and whose connectivity block
        # carries the classifier's verdict. Without lifting it here, that
        # deterministic root cause would be invisible at job level while the
        # raised-failure paths below report it. Additive only: ``status``,
        # ``stage`` and ``result`` are untouched.
        data_plane = _data_plane_classification(result)

        with jobs_lock:
            jobs[job_id]["status"] = "COMPLETED"
            jobs[job_id]["stage"] = "COMPLETED"
            jobs[job_id]["result"] = result
            if data_plane:
                jobs[job_id]["root_cause"] = data_plane["root_cause"]
                jobs[job_id]["confidence"] = data_plane["confidence"]
                jobs[job_id]["reason"] = data_plane["reason"]
                jobs[job_id]["evidence"] = data_plane["evidence"]

    except ValueError as e:
        with jobs_lock:
            jobs[job_id]["status"] = "FAILED"
            jobs[job_id]["stage"] = "CONFIGURATION"
            jobs[job_id]["error"] = str(e)
            # A configuration rejection is NOT an IPsec runtime failure: the
            # pipeline never got far enough to negotiate anything. Label it so a
            # result set never conflates "the device is misconfigured" with
            # "the tunnel came up and then broke".
            jobs[job_id]["root_cause"] = diagnose.UNSUPPORTED_CONFIGURATION
            jobs[job_id]["confidence"] = diagnose.DETERMINISTIC
            jobs[job_id]["reason"] = str(e)
            jobs[job_id]["evidence"] = {
                "requested_mode": config.get("mode"),
                "requested_address_family": config.get("address_family"),
                "requested_nat": config.get("nat"),
            }

    except Exception as e:
        with jobs_lock:
            failed_stage = jobs[job_id]["stage"]
            if failed_stage not in PIPELINE_STAGES:
                failed_stage = "EXPERIMENT"
            jobs[job_id]["status"] = "FAILED"
            jobs[job_id]["stage"] = failed_stage
            jobs[job_id]["error"] = str(e)
            # Deterministic root cause, when the failure produced one. This is
            # purely additive: a failure without a classification simply has no
            # ``root_cause`` field, exactly as before.
            classification = getattr(e, "classification", None)
            if classification:
                jobs[job_id]["root_cause"] = classification["root_cause"]
                jobs[job_id]["confidence"] = classification["confidence"]
                jobs[job_id]["reason"] = classification["reason"]
                jobs[job_id]["evidence"] = classification["evidence"]

    finally:
        with jobs_lock:
            active_job_id = None
        TESTBED_LOCK.release(EXPERIMENT, job_id)


@app.post("/experiments")
def create_experiment(config: ExperimentConfig):
    global active_job_id

    config_data = config.model_dump()

    with jobs_lock:
        if active_job_id is not None:
            active = jobs.get(active_job_id)

            if active and active["status"] == "RUNNING":
                raise HTTPException(
                    status_code=409,
                    detail="Another experiment is already running.",
                )

            active_job_id = None

        job_id = str(uuid4())

        # Shared testbed: a dataset run and a manual experiment can never use
        # the testbed at the same time.
        reserved, owner = TESTBED_LOCK.try_reserve(EXPERIMENT, job_id)
        if not reserved:
            kind, owner_id = owner
            raise HTTPException(
                status_code=409,
                detail=(
                    f"The shared testbed is in use by {kind} '{owner_id}'; "
                    "a manual experiment cannot start now."
                ),
            )

        jobs[job_id] = {
            "status": "QUEUED",
            "stage": "QUEUED",
            "result": None,
            "error": None,
            # Deterministic root-cause fields, absent until a failure actually
            # classifies one. See controller/diagnose.py.
            "root_cause": None,
            "confidence": None,
            "reason": None,
            "evidence": None,
        }

        active_job_id = job_id

    thread = Thread(
        target=execute_job,
        args=(job_id, config_data),
        daemon=True,
    )
    thread.start()

    return {
        "job_id": job_id,
        "status": "QUEUED",
    }


@app.get("/experiments/{job_id}")
def get_experiment(job_id: str):
    with jobs_lock:
        job = jobs.get(job_id)

        if job is None:
            raise HTTPException(
                status_code=404,
                detail="Experiment job not found.",
            )

        return {
            "job_id": job_id,
            **job,
        }
