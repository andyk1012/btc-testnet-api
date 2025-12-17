import os
import re
import subprocess
import sys
from typing import Optional

from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

app = FastAPI(title="BTC Testnet API (Educational)")

# ---------------------------
# Security / config
# ---------------------------

def _parse_origins() -> list[str]:
    raw = os.getenv(
        "ALLOWED_ORIGINS",
        "https://eurocoinmarket.com,https://www.eurocoinmarket.com",
    )
    origins = [o.strip() for o in raw.split(",") if o.strip()]
    return origins or ["https://eurocoinmarket.com", "https://www.eurocoinmarket.com"]

ALLOWED_ORIGINS = _parse_origins()
API_KEY = os.getenv("API_KEY", "").strip()

DEMO_WALLET = os.getenv("DEMO_WALLET", "alic").strip()
DEMO_PASSWORD = os.getenv("DEMO_PASSWORD", "").strip()

if not DEMO_PASSWORD:
    # Don't crash import-time on Render, but you SHOULD set it.
    print("WARNING: DEMO_PASSWORD is not set. /send will fail until configured.")

# CORS (restricted)
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

# ---------------------------
# Models
# ---------------------------

class SendReq(BaseModel):
    to_address: str = Field(..., min_length=26)
    amount_btc: float = Field(..., gt=0, le=0.0005)  # demo cap
    fee_rate: Optional[int] = Field(None, ge=1, le=50)

class CreateWalletReq(BaseModel):
    name: str = Field(..., min_length=1, max_length=32)
    password: str = Field(..., min_length=1, max_length=128)

# ---------------------------
# Helpers
# ---------------------------

def require_api_key(x_api_key: Optional[str]):
    if not API_KEY:
        raise HTTPException(500, detail="Server not configured: API_KEY missing.")
    if not x_api_key or x_api_key.strip() != API_KEY:
        raise HTTPException(401, detail="Unauthorized (missing/invalid X-API-KEY).")

def run_cli(cmd: list[str], timeout_s: int = 35) -> str:
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"

    try:
        p = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            env=env,
            timeout=timeout_s,
        )
    except subprocess.TimeoutExpired:
        raise HTTPException(
            status_code=504,
            detail=f"CLI timeout after {timeout_s}s. Try again.",
        )

    out = (p.stdout or "") + "\n" + (p.stderr or "")
    if p.returncode != 0:
        raise HTTPException(status_code=400, detail=out.strip()[:5000])
    return out.strip()

# ---------------------------
# Routes
# ---------------------------

@app.get("/")
def root():
    return {
        "service": "btc-testnet-api",
        "ok": True,
        "allowed_origins": ALLOWED_ORIGINS,
    }

@app.get("/health")
def health():
    return {"ok": True}

@app.post("/btc-testnet/create-wallet")
def create_wallet(req: CreateWalletReq, x_api_key: Optional[str] = Header(None)):
    require_api_key(x_api_key)

    out = run_cli([
        sys.executable, "btc_testnet.py", "create-wallet",
        req.name,
        "--password", req.password
    ])

    # Accept typical testnet address prefixes: m/n (P2PKH), 2 (P2SH)
    m = re.search(r"Address:\s*([mn2][a-km-zA-HJ-NP-Z1-9]{25,39})", out)
    if not m:
        raise HTTPException(500, detail="Wallet created but address not found in output.")
    return {"wallet": req.name, "address": m.group(1)}

@app.get("/btc-testnet/balance")
def balance(wallet: str):
    out = run_cli([
        sys.executable, "btc_testnet.py", "balance",
        "--wallet", wallet
    ])
    return {"wallet": wallet, "raw": out}

@app.post("/btc-testnet/send")
def send(req: SendReq, x_api_key: Optional[str] = Header(None)):
    require_api_key(x_api_key)

    if not DEMO_PASSWORD:
        raise HTTPException(500, detail="Server not configured: DEMO_PASSWORD missing.")

    cmd = [
        sys.executable, "btc_testnet.py", "send",
        "--from-wallet", DEMO_WALLET,
        "--password", DEMO_PASSWORD,
        "--to-address", req.to_address,
        "--amount-btc", str(req.amount_btc),
    ]

    if req.fee_rate is not None:
        cmd += ["--fee-rate", str(req.fee_rate)]

    out = run_cli(cmd, timeout_s=45)

    m = re.search(r"TXID:\s*([0-9a-fA-F]{16,64})", out)
    if not m:
        raise HTTPException(500, detail=("TXID not found. Output:\n" + out)[:5000])

    txid = m.group(1)
    return {
        "txid": txid,
        "explorer": f"https://blockstream.info/testnet/tx/{txid}",
    }
