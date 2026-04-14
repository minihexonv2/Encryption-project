import os, json, time, hashlib, base64, statistics
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey



def canon(x):
    return json.dumps(x, sort_keys=True, separators=(",", ":")).encode()

def sha256hex(x):
    return hashlib.sha256(x).hexdigest()

def b64(x):
    return base64.b64encode(x).decode()

def mean_sd(vals):
    return statistics.mean(vals), statistics.stdev(vals) if len(vals) > 1 else 0.0

def fmt(pair):
    return "N/A" if pair is None else f"{pair[0]:.2f} ± {pair[1]:.2f}"



def aes_enc(key, data):
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, data, None)
    return nonce, ct

def aes_dec(key, nonce, ct):
    return AESGCM(key).decrypt(nonce, ct, None)



def split_xor(secret):
    a = os.urandom(len(secret))
    b = bytes(x ^ y for x, y in zip(secret, a))
    return a, b

def join_xor(a, b):
    if len(a) != len(b):
        raise ValueError("Shares must have same length")
    return bytes(x ^ y for x, y in zip(a, b))



def issue_token(sk, file_id, requester_id, case_id, ttl=300):
    now = datetime.now(timezone.utc).replace(microsecond=0)
    payload = {
        "file_id": file_id,
        "requester_id": requester_id,
        "case_id": case_id,
        "approval_time": now.isoformat().replace("+00:00", "Z"),
        "expiry_time": (now + timedelta(seconds=ttl)).isoformat().replace("+00:00", "Z"),
    }
    sig = sk.sign(canon(payload))
    return {"payload": payload, "signature": sig}

def verify_token(pk, token, expected_file_id):
    payload = token["payload"]
    pk.verify(token["signature"], canon(payload))

    required = {"file_id", "requester_id", "case_id", "approval_time", "expiry_time"}
    if set(payload.keys()) != required:
        raise ValueError("Bad token fields")
    if payload["file_id"] != expected_file_id:
        raise ValueError("Token bound to different file")

    expiry = datetime.fromisoformat(payload["expiry_time"].replace("Z", "+00:00"))
    if datetime.now(timezone.utc) > expiry:
        raise ValueError("Token expired")



def audit_add(log, event_type, case_id, file_id, actor):
    prev = log[-1]["hash"] if log else "GENESIS"
    body = {
        "previous_hash": prev,
        "event_type": event_type,
        "case_id": case_id,
        "file_id": file_id,
        "actor_label": actor,
        "timestamp": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    }
    row = dict(body)
    row["hash"] = sha256hex(canon(body))
    log.append(row)

def audit_verify(log):
    prev = "GENESIS"
    for row in log:
        body = {
            "previous_hash": row["previous_hash"],
            "event_type": row["event_type"],
            "case_id": row["case_id"],
            "file_id": row["file_id"],
            "actor_label": row["actor_label"],
            "timestamp": row["timestamp"],
        }
        if row["previous_hash"] != prev:
            return False
        if row["hash"] != sha256hex(canon(body)):
            return False
        prev = row["hash"]
    return True

def audit_size(log):
    return len(canon({"audit_records": log}))



def package_size(d):
    out = {}
    for k, v in d.items():
        out[k] = b64(v) if isinstance(v, (bytes, bytearray)) else v
    return len(canon(out))



def no_escrow(data):
    t0 = time.perf_counter()
    dek = os.urandom(32)
    file_id = sha256hex(data)[:12]
    n_file, c_file = aes_enc(dek, data)
    enroll = (time.perf_counter() - t0) * 1000

    t1 = time.perf_counter()
    correct = aes_dec(dek, n_file, c_file) == data
    normal = (time.perf_counter() - t1) * 1000

    size = package_size({
        "scheme": "aes-256-gcm/no-escrow",
        "file_id": file_id,
        "file_nonce": n_file,
        "ciphertext": c_file,
    })

    return {
        "enroll": enroll,
        "normal": normal,
        "recovery": None,
        "size": size,
        "correct": correct,
        "auth_recovery": None,
        "one_party_blocked": None,
        "audit_valid": None,
        "audit_size": 0,
    }

def single_escrow(data):
    t0 = time.perf_counter()
    dek = os.urandom(32)
    rk = os.urandom(32)
    file_id = sha256hex(data)[:12]

    n_file, c_file = aes_enc(dek, data)
    n_wrap, c_wrap = aes_enc(rk, dek)
    enroll = (time.perf_counter() - t0) * 1000

    t1 = time.perf_counter()
    correct = aes_dec(dek, n_file, c_file) == data
    normal = (time.perf_counter() - t1) * 1000

    t2 = time.perf_counter()
    recovered_dek = aes_dec(rk, n_wrap, c_wrap)
    auth_recovery = aes_dec(recovered_dek, n_file, c_file) == data
    recovery = (time.perf_counter() - t2) * 1000

    size = package_size({
        "scheme": "aes-256-gcm/single-escrow",
        "file_id": file_id,
        "file_nonce": n_file,
        "ciphertext": c_file,
        "wrap_nonce": n_wrap,
        "wrapped_dek": c_wrap,
    })

    return {
        "enroll": enroll,
        "normal": normal,
        "recovery": recovery,
        "size": size,
        "correct": correct,
        "auth_recovery": auth_recovery,
        "one_party_blocked": False,
        "audit_valid": None,
        "audit_size": 0,
    }

def dual_control(data, sk, pk, requester_id, case_id):
    log = []

    t0 = time.perf_counter()
    dek = os.urandom(32)
    rk = os.urandom(32)
    file_id = sha256hex(data)[:12]

    n_file, c_file = aes_enc(dek, data)
    n_wrap, c_wrap = aes_enc(rk, dek)
    share_a, share_b = split_xor(rk)
    audit_add(log, "ENROLL", case_id, file_id, "client")
    enroll = (time.perf_counter() - t0) * 1000

    t1 = time.perf_counter()
    correct = aes_dec(dek, n_file, c_file) == data
    normal = (time.perf_counter() - t1) * 1000

    one_party_blocked = False
    try:
        fake_b = b"\x00" * len(share_a)
        bad_rk = join_xor(share_a, fake_b)
        aes_dec(bad_rk, n_wrap, c_wrap)
    except Exception:
        one_party_blocked = True
        audit_add(log, "UNAUTHORIZED_RECOVERY_BLOCKED", case_id, file_id, "recovery-service")

    t2 = time.perf_counter()
    token = issue_token(sk, file_id, requester_id, case_id)
    audit_add(log, "RECOVERY_APPROVED", case_id, file_id, "approval-service")

    verify_token(pk, token, file_id)
    full_rk = join_xor(share_a, share_b)
    audit_add(log, "RK_RECONSTRUCTED", case_id, file_id, "recovery-service")

    recovered_dek = aes_dec(full_rk, n_wrap, c_wrap)
    auth_recovery = aes_dec(recovered_dek, n_file, c_file) == data
    audit_add(log, "RECOVERY_COMPLETED", case_id, file_id, "recovery-service")
    recovery = (time.perf_counter() - t2) * 1000

    size = package_size({
        "scheme": "aes-256-gcm/dual-control-escrow",
        "file_id": file_id,
        "file_nonce": n_file,
        "ciphertext": c_file,
        "wrap_nonce": n_wrap,
        "wrapped_dek": c_wrap,
    })

    return {
        "enroll": enroll,
        "normal": normal,
        "recovery": recovery,
        "size": size,
        "correct": correct,
        "auth_recovery": auth_recovery,
        "one_party_blocked": one_party_blocked,
        "audit_valid": audit_verify(log),
        "audit_size": audit_size(log),
    }



def summarize(name, rows):
    enroll_m, enroll_sd = mean_sd([r["enroll"] for r in rows])
    normal_m, normal_sd = mean_sd([r["normal"] for r in rows])
    size_m, _ = mean_sd([r["size"] for r in rows])
    audit_m, _ = mean_sd([r["audit_size"] for r in rows])

    rec_vals = [r["recovery"] for r in rows if r["recovery"] is not None]
    recovery_pair = mean_sd(rec_vals) if rec_vals else None

    def all_or_none(key):
        vals = [r[key] for r in rows if r[key] is not None]
        return all(vals) if vals else None

    return {
        "name": name,
        "enroll": (enroll_m, enroll_sd),
        "normal": (normal_m, normal_sd),
        "recovery": recovery_pair,
        "size": size_m,
        "correct": all(r["correct"] for r in rows),
        "auth_recovery": all_or_none("auth_recovery"),
        "one_party_blocked": all_or_none("one_party_blocked"),
        "audit_valid": all_or_none("audit_valid"),
        "audit_size": audit_m,
    }


def benchmark(iters=1000, file_size=512 * 1024):
    data = os.urandom(file_size)  # one fixed test file reused across all runs
    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key()

    no_rows = [no_escrow(data) for _ in range(iters)]
    single_rows = [single_escrow(data) for _ in range(iters)]
    dual_rows = [dual_control(data, sk, pk, f"requester-{i:04d}", f"case-{i:04d}") for i in range(iters)]

    results = [
        summarize("No escrow", no_rows),
        summarize("Single escrow", single_rows),
        summarize("Dual-control escrow", dual_rows),
    ]

    print("\nTable 3. Measured performance and storage results (mean ± SD, n = %d)\n" % iters)
    print(f"{'Architecture':<22} {'Enroll (ms)':<18} {'Normal decrypt (ms)':<22} {'Recovery (ms)':<18} {'Package size (bytes)':<20}")
    print("-" * 105)
    for r in results:
        print(f"{r['name']:<22} {fmt(r['enroll']):<18} {fmt(r['normal']):<22} {fmt(r['recovery']):<18} {r['size']:.0f}")

    print("\nTable 4. Security and correctness outcomes across %d iterations\n" % iters)
    print(f"{'Architecture':<22} {'Correct normal decryption':<28} {'Authorized recovery successful':<32} {'One-party recovery blocked':<28} {'Audit chain valid':<20}")
    print("-" * 140)
    for r in results:
        print(f"{r['name']:<22} {str(r['correct']):<28} {str(r['auth_recovery']):<32} {str(r['one_party_blocked']):<28} {str(r['audit_valid']):<20}")

    dual = results[2]
    print("\nDual-control mean audit-chain size (bytes):", f"{dual['audit_size']:.0f}")



if __name__ == "__main__":
    benchmark(iters=1000, file_size=512 * 1024)