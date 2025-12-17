import os
import re
import subprocess
import sys

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

app = FastAPI()

# -------------------------
# CORS (open for demo; restrict later)
# -------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -------------------------
# Request models
# -------------------------

class SendReq(BaseModel):
    to_address: str = Field(..., min_length=26)
    amount_btc: float = Field(..., gt=0, le=0.0005)   # demo safety cap
    fee_rate: int | None = Field(
        default=None,
        ge=1,
        le=50,
        description="Optional fee rate in sat/vB (default = 5)"
    )

class CreateWalletReq(BaseModel):
    name: str = Field(..., min_length=1, max_length=32)
    password: str = Field(..., min_length=1, max_length=128)

# -------------------------
# Helper to run CLI safely
# -------------------------

def run_cli(cmd: list[str]) -> str:
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"

    p = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        env=env
    )

    out = (p.stdout or "") + "\n" + (p.stderr or "")
    if p.returncode != 0:
        raise HTTPException(status_code=400, detail=out.strip())

    return out.strip()

# -------------------------
# Health
# -------------------------

@app.get("/health")
def health():
    return {"ok": True}

# -------------------------
# Create wallet (testnet)
# -------------------------

@app.post("/btc-testnet/create-wallet")
def create_wallet(req: CreateWalletReq):
    out = run_cli([
        sys.executable,
        "btc_testnet.py",
        "create-wallet",
        req.name,
        "--password",
        req.password,
    ])

    m = re.search(r"Address:\s*([mn][a-km-zA-HJ-NP-Z1-9]{25,34})", out)
    if not m:
        raise HTTPException(
            status_code=500,
            detail="Wallet created but address not found in output."
        )

    return {
        "wallet": req.name,
        "address": m.group(1),
    }

# -------------------------
# Balance
# -------------------------

@app.get("/btc-testnet/balance")
def balance(wallet: str):
    out = run_cli([
        sys.executable,
        "btc_testnet.py",
        "balance",
        "--wallet",
        wallet,
    ])

    return {
        "wallet": wallet,
        "raw": out,
    }

# -------------------------
# Send testnet BTC
# -------------------------

@app.post("/btc-testnet/send")
def send(req: SendReq):
    wallet = os.getenv("DEMO_WALLET", "alic")
    pwd = os.getenv("DEMO_PASSWORD", "")

    if not pwd:
        raise HTTPException(
            status_code=500,
            detail="Server not configured: DEMO_PASSWORD missing."
        )

    # Build command
    cmd = [
        sys.executable,
        "btc_testnet.py",
        "send",
        "--from-wallet",
        wallet,
        "--password",
        pwd,
        "--to-address",
        req.to_address,
        "--amount-btc",
        str(req.amount_btc),
    ]

    # ✅ Fee handling (THIS FIXES YOUR ISSUE)
    if req.fee_rate is not None:
        cmd += ["--fee-rate", str(req.fee_rate)]
    else:
        # Safe default for testnet
        cmd += ["--fee-rate", "5"]

    out = run_cli(cmd)

    m = re.search(r"TXID:\s*([0-9a-fA-F]{16,64})", out)
    if not m:
        raise HTTPException(
            status_code=500,
            detail="TXID not found in output:\n" + out
        )

    txid = m.group(1)

    return {
        "txid": txid,
        "explorer": f"https://blockstream.info/testnet/tx/{txid}",
    }
