import os, re, subprocess, sys
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # restrict later
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class SendReq(BaseModel):
    to_address: str = Field(..., min_length=26)
    amount_btc: float = Field(..., gt=0, le=0.0005)

@app.get("/health")
def health():
    return {"ok": True}

@app.post("/btc-testnet/send")
def send(req: SendReq):
    wallet = os.getenv("DEMO_WALLET", "alic")
    pwd = os.getenv("DEMO_PASSWORD", "1234")

    cmd = [
        sys.executable, "btc_testnet.py", "send",
        "--from-wallet", wallet,
        "--password", pwd,
        "--to-address", req.to_address,
        "--amount-btc", str(req.amount_btc),
    ]

    # 🔧 FIX: force UTF-8 output so Windows doesn't crash on special characters
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
        raise HTTPException(400, out.strip())

    m = re.search(r"TXID:\s*([0-9a-fA-F]{16,64})", out)
    if not m:
        raise HTTPException(500, "TXID not found")

    txid = m.group(1)
    return {
        "txid": txid,
        "explorer": f"https://blockstream.info/testnet/tx/{txid}",
    }
