# Bitcoin Testnet Tools (Educational) — PURE PYTHON (Windows-friendly)
# - Creates real Bitcoin TESTNET keys/addresses (P2PKH)
# - Builds, signs, and broadcasts a real testnet transaction (legacy P2PKH)
# - Broadcasts via Blockstream Testnet API
#
# IMPORTANT:
# - This is NOT "flash" funds. You must fund your testnet address via a faucet.
# - Testnet coins have no real-world value, but rules are real.

import argparse
import hashlib
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

import requests
from ecdsa import SECP256k1, SigningKey

# -------------------------
# Wallet storage location
# -------------------------
# Render-friendly: set WALLETS_DIR=/var/data/wallets
WALLETS_DIR = os.environ.get("WALLETS_DIR", "wallets")

BASE = Path(__file__).resolve().parent
WALLETS = Path(WALLETS_DIR)
if not WALLETS.is_absolute():
    WALLETS = (BASE / WALLETS).resolve()
WALLETS.mkdir(parents=True, exist_ok=True)

API = "https://blockstream.info/testnet/api"

# -------------------------
# Helpers: encoding/crypto
# -------------------------

ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def ripemd160(b: bytes) -> bytes:
    h = hashlib.new("ripemd160")
    h.update(b)
    return h.digest()


def hash160(b: bytes) -> bytes:
    return ripemd160(sha256(b))


def dsha256(b: bytes) -> bytes:
    return sha256(sha256(b))


def b58encode(b: bytes) -> str:
    # leading zeros
    n_zeros = 0
    for c in b:
        if c == 0:
            n_zeros += 1
        else:
            break

    num = int.from_bytes(b, "big")
    out = bytearray()
    while num > 0:
        num, rem = divmod(num, 58)
        out.append(ALPHABET[rem])
    out.reverse()
    return (ALPHABET[0:1] * n_zeros + out).decode()


def b58check_encode(payload: bytes) -> str:
    chk = dsha256(payload)[:4]
    return b58encode(payload + chk)


def b58decode(s: str) -> bytes:
    num = 0
    for ch in s.encode():
        num *= 58
        idx = ALPHABET.find(bytes([ch]))
        if idx == -1:
            raise ValueError("Invalid base58 char")
        num += idx

    # leading zeros
    n_zeros = 0
    for ch in s.encode():
        if ch == ALPHABET[0]:
            n_zeros += 1
        else:
            break

    b = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
    return b"\x00" * n_zeros + b


def b58decode_check(s: str) -> bytes:
    b = b58decode(s)
    if len(b) < 5:
        raise ValueError("Too short")
    payload, chk = b[:-4], b[-4:]
    if dsha256(payload)[:4] != chk:
        raise ValueError("Bad checksum")
    return payload


def varint(n: int) -> bytes:
    if n < 0xfd:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + n.to_bytes(2, "little")
    if n <= 0xFFFFFFFF:
        return b"\xfe" + n.to_bytes(4, "little")
    return b"\xff" + n.to_bytes(8, "little")


def ser_string(b: bytes) -> bytes:
    return varint(len(b)) + b


def privkey_to_wif_testnet(priv: bytes, compressed: bool = True) -> str:
    # testnet WIF prefix 0xEF
    payload = b"\xef" + priv + (b"\x01" if compressed else b"")
    return b58check_encode(payload)


def pubkey_from_priv(priv: bytes, compressed: bool = True) -> bytes:
    sk = SigningKey.from_string(priv, curve=SECP256k1)
    vk = sk.get_verifying_key()
    x = vk.pubkey.point.x()
    y = vk.pubkey.point.y()
    xb = x.to_bytes(32, "big")

    if not compressed:
        return b"\x04" + xb + y.to_bytes(32, "big")
    return (b"\x02" if (y % 2 == 0) else b"\x03") + xb


def p2pkh_address_testnet(pubkey: bytes) -> str:
    # testnet p2pkh prefix 0x6F
    payload = b"\x6f" + hash160(pubkey)
    return b58check_encode(payload)


def scriptpubkey_p2pkh(address: str) -> bytes:
    payload = b58decode_check(address)
    if payload[0] not in (0x6F, 0x00):
        raise ValueError("Not a P2PKH address")
    h160 = payload[1:]
    # OP_DUP OP_HASH160 <20> <h160> OP_EQUALVERIFY OP_CHECKSIG
    return b"\x76\xa9\x14" + h160 + b"\x88\xac"


def script_sig_p2pkh(sig_der_plus_hashtype: bytes, pubkey: bytes) -> bytes:
    return ser_string(sig_der_plus_hashtype) + ser_string(pubkey)


def der_sig(r: int, s: int) -> bytes:
    def ser_int(x: int) -> bytes:
        b = x.to_bytes((x.bit_length() + 7) // 8 or 1, "big")
        if b[0] & 0x80:
            b = b"\x00" + b
        return b

    rb = ser_int(r)
    sb = ser_int(s)
    return (
        b"\x30"
        + bytes([2 + len(rb) + 2 + len(sb)])
        + b"\x02"
        + bytes([len(rb)])
        + rb
        + b"\x02"
        + bytes([len(sb)])
        + sb
    )


# -------------------------
# Transaction building
# -------------------------

@dataclass
class UTXO:
    txid: str
    vout: int
    value: int  # satoshis


def little_endian_txid(txid_hex: str) -> bytes:
    return bytes.fromhex(txid_hex)[::-1]


def tx_serialize(version: int, txins: List[bytes], txouts: List[bytes], locktime: int) -> bytes:
    return (
        version.to_bytes(4, "little")
        + varint(len(txins)) + b"".join(txins)
        + varint(len(txouts)) + b"".join(txouts)
        + locktime.to_bytes(4, "little")
    )


def txin_serialize(txid: str, vout: int, script_sig: bytes, sequence: int = 0xFFFFFFFF) -> bytes:
    return (
        little_endian_txid(txid)
        + vout.to_bytes(4, "little")
        + ser_string(script_sig)
        + sequence.to_bytes(4, "little")
    )


def txout_serialize(value: int, script_pubkey: bytes) -> bytes:
    return value.to_bytes(8, "little") + ser_string(script_pubkey)


def estimate_vbytes_p2pkh(n_in: int, n_out: int) -> int:
    return 10 + n_in * 148 + n_out * 34


def fetch_utxos(address: str) -> List[UTXO]:
    r = requests.get(f"{API}/address/{address}/utxo", timeout=30)
    r.raise_for_status()
    return [UTXO(txid=u["txid"], vout=int(u["vout"]), value=int(u["value"])) for u in r.json()]


def broadcast(raw_hex: str) -> str:
    r = requests.post(f"{API}/tx", data=raw_hex, timeout=30)
    r.raise_for_status()
    return r.text.strip()


# -------------------------
# Wallet storage + encryption
# -------------------------

def load_json(path: Path, default):
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8"))
    return default


def save_json(path: Path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2), encoding="utf-8")


def pbkdf2_key(password: str, salt: bytes, rounds: int = 200_000, dklen: int = 32) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, rounds, dklen=dklen)


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def encrypt_secret(secret_bytes: bytes, password: str) -> dict:
    import secrets
    salt = secrets.token_bytes(16)
    key = pbkdf2_key(password, salt, dklen=len(secret_bytes))
    ct = xor_bytes(secret_bytes, key)
    mac = hashlib.sha256(salt + ct + password.encode("utf-8")).hexdigest()
    return {
        "enc": ct.hex(),
        "salt": salt.hex(),
        "mac": mac,
        "kdf": {"name": "pbkdf2-hmac-sha256", "rounds": 200000},
    }


def decrypt_secret(enc_obj: dict, password: str) -> bytes:
    salt = bytes.fromhex(enc_obj["salt"])
    ct = bytes.fromhex(enc_obj["enc"])
    mac = hashlib.sha256(salt + ct + password.encode("utf-8")).hexdigest()
    if mac != enc_obj.get("mac"):
        raise SystemExit("Wrong password.")
    key = pbkdf2_key(password, salt, dklen=len(ct))
    return xor_bytes(ct, key)


def wallet_path(name: str) -> Path:
    return WALLETS / f"btc_testnet_{name}.json"


def create_wallet(name: str, password: Optional[str]) -> str:
    if wallet_path(name).exists():
        raise SystemExit(f"Wallet '{name}' already exists.")

    priv = os.urandom(32)
    pub = pubkey_from_priv(priv, compressed=True)
    addr = p2pkh_address_testnet(pub)
    wif = privkey_to_wif_testnet(priv, compressed=True)

    wallet = {
        "name": name,
        "network": "bitcoin-testnet",
        "address": addr,
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "note": "REAL Bitcoin TESTNET P2PKH wallet (fund via faucet).",
    }

    if password:
        wallet["wif_encrypted"] = encrypt_secret(wif.encode("utf-8"), password)
    else:
        wallet["wif_plain"] = wif

    save_json(wallet_path(name), wallet)
    return addr


def load_wif(name: str, password: Optional[str]) -> str:
    w = load_json(wallet_path(name), None)
    if not w:
        raise SystemExit(f"Wallet '{name}' not found.")

    if "wif_plain" in w:
        return w["wif_plain"]

    if "wif_encrypted" in w:
        if not password:
            raise SystemExit("This wallet is encrypted. Provide --password.")
        return decrypt_secret(w["wif_encrypted"], password).decode("utf-8")

    raise SystemExit("Wallet missing WIF.")


def load_address(name: str) -> str:
    w = load_json(wallet_path(name), None)
    if not w:
        raise SystemExit(f"Wallet '{name}' not found.")
    return w["address"]


# -------------------------
# Commands
# -------------------------

def cmd_create(args):
    addr = create_wallet(args.name, args.password)
    print("Created Bitcoin TESTNET wallet (P2PKH)")
    print(f"Name:    {args.name}")
    print(f"Address: {addr}")
    print("\nFund this address using a testnet faucet, then you can broadcast a real testnet tx.")


def cmd_balance(args):
    address = args.address or (load_address(args.wallet) if args.wallet else None)
    if not address:
        raise SystemExit("Provide --address or --wallet.")

    r = requests.get(f"{API}/address/{address}", timeout=30)
    r.raise_for_status()
    d = r.json()

    confirmed = int(d["chain_stats"]["funded_txo_sum"]) - int(d["chain_stats"]["spent_txo_sum"])
    unconf = int(d["mempool_stats"]["funded_txo_sum"]) - int(d["mempool_stats"]["spent_txo_sum"])

    print(f"Address: {address}")
    print(f"Confirmed:   {confirmed} sat ({confirmed/1e8:.8f} tBTC)")
    print(f"Unconfirmed: {unconf} sat ({unconf/1e8:.8f} tBTC)")


def cmd_send(args):
    wif = load_wif(args.from_wallet, args.password)

    payload = b58decode_check(wif)
    compressed = (len(payload) == 34 and payload[-1] == 0x01)
    priv = payload[1:-1] if compressed else payload[1:]
    pub = pubkey_from_priv(priv, compressed=True)
    from_address = p2pkh_address_testnet(pub)

    utxos = fetch_utxos(from_address)
    if not utxos:
        raise SystemExit("No UTXOs found. Fund your testnet address via a faucet first.")

    amount_sat = int(round(args.amount_btc * 100_000_000))
    if amount_sat <= 0:
        raise SystemExit("Amount must be > 0")

    # ✅ Safe fee handling
    fr = args.fee_rate if args.fee_rate is not None else 5
    fr = max(1, min(int(fr), 50))

    # coin selection largest-first
    utxos_sorted = sorted(utxos, key=lambda u: u.value, reverse=True)
    selected: List[UTXO] = []
    total_in = 0
    for u in utxos_sorted:
        selected.append(u)
        total_in += u.value
        fee_est = fr * estimate_vbytes_p2pkh(len(selected), 2)
        if total_in >= amount_sat + fee_est:
            break

    if not selected:
        raise SystemExit("Could not select inputs.")

    vbytes = estimate_vbytes_p2pkh(len(selected), 2)
    fee = fr * vbytes

    if total_in < amount_sat + fee:
        raise SystemExit(
            f"Insufficient funds. total_in={total_in} sat, need={amount_sat+fee} sat (incl fee={fee})."
        )

    change = total_in - amount_sat - fee
    change_addr = args.change_address or from_address

    scriptpk_from = scriptpubkey_p2pkh(from_address)

    # unsigned inputs (empty scriptsigs)
    txins = [txin_serialize(u.txid, u.vout, b"", 0xFFFFFFFF) for u in selected]

    txouts = [txout_serialize(amount_sat, scriptpubkey_p2pkh(args.to_address))]

    # avoid dust change
    if change >= 600:
        txouts.append(txout_serialize(change, scriptpubkey_p2pkh(change_addr)))
    else:
        fee += change
        change = 0

    version = 1
    locktime = 0

    sk = SigningKey.from_string(priv, curve=SECP256k1)
    final_txins = []
    for idx, u in enumerate(selected):
        tmp_ins = []
        for j, uu in enumerate(selected):
            script = scriptpk_from if j == idx else b""
            tmp_ins.append(txin_serialize(uu.txid, uu.vout, script, 0xFFFFFFFF))

        preimage = tx_serialize(version, tmp_ins, txouts, locktime) + (1).to_bytes(4, "little")
        z = dsha256(preimage)

        sig = sk.sign_digest(z, sigencode=lambda r, s, order: der_sig(r, s))
        sig_plus = sig + b"\x01"  # SIGHASH_ALL
        scriptsig = script_sig_p2pkh(sig_plus, pub)
        final_txins.append(txin_serialize(u.txid, u.vout, scriptsig, 0xFFFFFFFF))

    raw = tx_serialize(version, final_txins, txouts, locktime)
    raw_hex = raw.hex()

    print("Built REAL Bitcoin TESTNET transaction (legacy P2PKH, pure python)")
    print(f"From:   {from_address}")
    print(f"To:     {args.to_address}")
    print(f"Amount: {amount_sat} sat ({args.amount_btc} tBTC)")
    print(f"Fee:    {fee} sat (fee_rate={fr} sat/vB)")
    print(f"Change: {change} sat\n")

    if args.dry_run:
        print("DRY RUN enabled. Not broadcasting.")
        print("Raw TX hex (first 200 chars):")
        print(raw_hex[:200] + ("..." if len(raw_hex) > 200 else ""))
        return

    txid = broadcast(raw_hex)
    print("Broadcasted to Blockstream Testnet API.")
    print(f"TXID: {txid}")
    print("Verify by searching this TXID on a Bitcoin testnet explorer.")


def build_parser():
    p = argparse.ArgumentParser(prog="btc_testnet.py", description="Bitcoin TESTNET tools (Educational, pure python)")
    sub = p.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("create-wallet", help="Create a Bitcoin TESTNET wallet (P2PKH)")
    c.add_argument("name")
    c.add_argument("--password", help="Encrypt stored WIF with a password")
    c.set_defaults(func=cmd_create)

    b = sub.add_parser("balance", help="Check confirmed/unconfirmed balance via Blockstream API")
    b.add_argument("--wallet", help="Wallet name created with create-wallet")
    b.add_argument("--address", help="Any testnet P2PKH address")
    b.set_defaults(func=cmd_balance)

    s = sub.add_parser("send", help="Build, sign, and broadcast a real testnet TX (P2PKH)")
    s.add_argument("--from-wallet", required=True)
    s.add_argument("--password", help="Password if wallet is encrypted")
    s.add_argument("--to-address", required=True, help="Recipient testnet P2PKH address")
    s.add_argument("--amount-btc", type=float, required=True, help="Amount in tBTC (e.g. 0.0001)")
    s.add_argument("--fee-rate", type=int, help="Fee rate in sat/vB (optional, default=5)")
    s.add_argument("--change-address", help="Optional change address")
    s.add_argument("--dry-run", action="store_true", help="Build/sign but do not broadcast")
    s.set_defaults(func=cmd_send)

    return p


def main():
    args = build_parser().parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
