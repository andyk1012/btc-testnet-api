import os, re, subprocess, sys
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

app = FastAPI()

# CORS (restrict later to your website domain)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class SendReq(BaseModel):
    to_address: str = Field(..., min_length=26)
    amount_btc: float = Field(..., gt=0, le=0.0005)  # cap for demo safety
    fee_rate: int | None = Field(None, ge=1, le=50)  # optional

class CreateWalletReq(BaseModel):
    name: str = Field(..., min_length=1, max_length=32)
    password: str = Field(..., min_length=1, max_length=128)

def run_cli(cmd: list[str], timeout_s: int = 25) -> str:
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
            detail=f"CLI timeout after {timeout_s}s. Try again or reduce load.",
        )

    out = (p.stdout or "") + "\n" + (p.stderr or "")
    if p.returncode != 0:
        # keep it readable
        raise HTTPException(status_code=400, detail=out.strip()[:5000])
    return out.strip()

@app.get("/")
def root():
    return {"service": "btc-testnet-api", "ok": True}

@app.get("/health")
def health():
    return {"ok": True}

@app.post("/btc-testnet/create-wallet")
def create_wallet(req: CreateWalletReq):
    out = run_cli([
        sys.executable, "btc_testnet.py", "create-wallet",
        req.name,
        "--password", req.password
    ])
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
def send(req: SendReq):
    wallet = os.getenv("DEMO_WALLET", "alic")
    pwd = os.getenv("DEMO_PASSWORD", "")
    if not pwd:
        raise HTTPException(500, detail="Server not configured: DEMO_PASSWORD missing.")

    cmd = [
        sys.executable, "btc_testnet.py", "send",
        "--from-wallet", wallet,
        "--password", pwd,
        "--to-address", req.to_address,
        "--amount-btc", str(req.amount_btc),
    ]

    # Optional fee rate support (if your btc_testnet.py accepts it)
    if req.fee_rate is not None:
        cmd += ["--fee-rate", str(req.fee_rate)]

    out = run_cli(cmd, timeout_s=35)

    m = re.search(r"TXID:\s*([0-9a-fA-F]{16,64})", out)
    if not m:
        raise HTTPException(500, detail=("TXID not found. Output:\n" + out)[:5000])

    txid = m.group(1)
    return {
        "txid": txid,
        "explorer": f"https://blockstream.info/testnet/tx/{txid}",
    }
