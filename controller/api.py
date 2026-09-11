from pathlib import Path
from threading import Lock, Thread
from uuid import uuid4

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from .executor import run_experiment

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


class ExperimentConfig(BaseModel):
    mode: str
    address_family: str = "ipv4"
    ike: IKEConfig
    esp: ESPConfig


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
        "ike": {
            "version": 2,
            "encryption": ["aes128", "aes256"],
            "integrity": ["sha256", "sha384", "sha512"],
            "dh_groups": ["modp2048", "modp3072", "modp4096"],
        },
       "esp": {
    "encryption": [
        "aes128gcm16",
        "aes256gcm16",
        "aes128cbc",
        "aes256cbc",
    ],
    "integrity": [
        "sha256",
        "sha384",
        "sha512",
    ],
    "dh_groups": [
        "modp2048",
        "modp3072",
        "modp4096",
    ],
    "pfs": [True, False],
},
    }


def execute_job(job_id, config):
    global active_job_id

    with jobs_lock:
        jobs[job_id]["status"] = "RUNNING"
        jobs[job_id]["stage"] = "RUNNING"

    try:
        result = run_experiment(config)

        with jobs_lock:
            jobs[job_id]["status"] = "COMPLETED"
            jobs[job_id]["stage"] = "COMPLETED"
            jobs[job_id]["result"] = result

    except ValueError as e:
        with jobs_lock:
            jobs[job_id]["status"] = "FAILED"
            jobs[job_id]["stage"] = "CONFIGURATION"
            jobs[job_id]["error"] = str(e)

    except Exception as e:
        with jobs_lock:
            jobs[job_id]["status"] = "FAILED"
            jobs[job_id]["stage"] = "EXPERIMENT"
            jobs[job_id]["error"] = str(e)

    finally:
        with jobs_lock:
            active_job_id = None


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

        jobs[job_id] = {
            "status": "QUEUED",
            "stage": "QUEUED",
            "result": None,
            "error": None,
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
