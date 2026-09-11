from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from executor import run_experiment

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
    dh_group: str
    pfs: bool


class ExperimentConfig(BaseModel):
    mode: str
    ike: IKEConfig
    esp: ESPConfig


@app.get("/", include_in_schema=False)
def root():
    return FileResponse(FRONTEND_DIR / "index.html")


@app.get("/health")
def health():
    return {
        "status": "ok",
    }

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
            "encryption": ["aes128gcm16", "aes256gcm16"],
            "dh_groups": ["modp2048", "modp3072", "modp4096"],
            "pfs": [True, False],
        },
    }


@app.post("/experiments")
def create_experiment(config: ExperimentConfig):
    try:
        result = run_experiment(config.model_dump())
        return result

    except ValueError as e:
        raise HTTPException(
            status_code=400,
            detail=str(e),
        )

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=str(e),
        )
