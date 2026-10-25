"""Free local test: fake LLM + real server + fake grader. Usage: python test_local.py"""
import os, sys, json, time, hashlib, base64, subprocess, tempfile, threading, uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

PROFILE = "ga5-mailroom-action-gate/v2"
APP, LLM = 8123, 8124
LLM_CALLS = {"n": 0}


def canon(o): return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
def sha(o): return hashlib.sha256(canon(o).encode()).hexdigest()


class FakeLLM(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["content-length"])))
        dossiers = json.loads(body["messages"][1]["content"])
        LLM_CALLS["n"] += 1
        dec = [{"dossierId": d["dossierId"], "action": "no_action", "target": None,
                "payload": {"reasonCode": "INFORMATIONAL", "referenceId": "REF-" + d["dossierId"]},
                "evidence": [d["sources"][0]["lines"][0]["lineId"]]} for d in dossiers]
        out = json.dumps({"choices": [{"message": {"content": json.dumps({"decisions": dec})}}]}).encode()
        self.send_response(200); self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(out))); self.end_headers(); self.wfile.write(out)


def dossier(i, text="Where is my order?"):
    return {"dossierId": f"D{i}", "partition": "stable_core", "receivedAt": "2026-10-25T10:00:00Z",
            "mailbox": "support", "objective": "triage",
            "sources": [{"sourceId": f"S{i}", "kind": "email", "provenance": "external",
                         "title": "hi", "lines": [{"lineId": f"D{i}-L1", "text": text},
                                                  {"lineId": f"D{i}-L2", "text": "thanks"}]}]}


def new_key():
    sk = Ed25519PrivateKey.generate()
    raw = sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    x = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    return sk, {"algorithm": "Ed25519", "publicKeyJwk": {"kty": "OKP", "crv": "Ed25519", "x": x}}


def propose_body(eid, key_jwk, dossiers):
    return {"profile": PROFILE, "operation": "propose", "evaluationId": eid, "receiptVerifier": key_jwk,
            "corpus": {"coreId": "c", "auditId": "a", "stableCount": len(dossiers), "freshCount": 0},
            "allowedActions": ["create_draft", "update_internal_record", "send_approved_notice",
                               "request_confirmation", "quarantine_item", "no_action"],
            "dossiers": dossiers}


def make_receipts(sk, eid, digest, proposals, accepted_flags):
    rs = []
    for p, acc in zip(proposals, accepted_flags):
        view = {k: p.get(k) for k in ("dossierId", "callId", "action", "target", "payload")}
        view["evidence"] = sorted(p["evidence"])
        rec = {"dossierId": p["dossierId"], "callId": p["callId"], "action": p["action"],
               "accepted": acc, "proposalDigest": sha(view), "receiptId": uuid.uuid4().hex}
        sig = sk.sign(canon({"profile": PROFILE, "evaluationId": eid, "inputDigest": digest,
                             "receipt": rec}).encode())
        rs.append({**rec, "receiptSignature": base64.b64encode(sig).decode()})
    return rs


def post(url, body):
    return httpx.post(url, content=body if isinstance(body, str) else json.dumps(body),
                      headers={"content-type": "application/json"}, timeout=60)


results = []
def check(name, cond):
    results.append(cond); print(("PASS  " if cond else "FAIL  ") + name)


def main():
    threading.Thread(target=HTTPServer(("127.0.0.1", LLM), FakeLLM).serve_forever, daemon=True).start()
    tmp = tempfile.mkdtemp()
    env = dict(os.environ, DB_PATH=os.path.join(tmp, "t.db"), LLM_KEY="x", LLM_MODEL="fake",
               LLM_URL=f"http://127.0.0.1:{LLM}/v1/chat/completions")
    srv = subprocess.Popen([sys.executable, "-m", "uvicorn", "app:app", "--port", str(APP)],
                           cwd=os.path.dirname(os.path.abspath(__file__)), env=env,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    url = f"http://127.0.0.1:{APP}/"
    try:
        for _ in range(50):
            try: httpx.get(url, timeout=1); break
            except Exception: time.sleep(0.2)

        ds = [dossier(i) for i in range(8)]
        sk1, jwk1 = new_key()
        b1 = propose_body("eval-1", jwk1, ds)
        r = post(url, b1); j = r.json()
        check("propose returns 200 awaiting_receipts", r.status_code == 200 and j["status"] == "awaiting_receipts")
        check("one proposal per dossier", len(j["proposals"]) == len(ds))
        check("inputDigest correct", j["inputDigest"] == sha(ds))
        check("callIds unique", len({p["callId"] for p in j["proposals"]}) == len(ds))
        calls_after_first = LLM_CALLS["n"]
        check("model was called", calls_after_first > 0)

        r2 = post(url, b1)
        check("exact replay is byte-identical", r2.content == r.content)
        check("replay made no model call", LLM_CALLS["n"] == calls_after_first)

        changed = json.loads(json.dumps(b1)); changed["dossiers"][0]["sources"][0]["lines"][0]["text"] = "x"
        check("changed content same evaluationId -> 409", post(url, changed).status_code == 409)

        sk2, jwk2 = new_key()
        r3 = post(url, propose_body("eval-2", jwk2, ds)); j3 = r3.json()
        check("second evaluation makes no model call", LLM_CALLS["n"] == calls_after_first)
        check("stable callIds across evaluations",
              [p["callId"] for p in j["proposals"]] == [p["callId"] for p in j3["proposals"]])

        bad_op = dict(b1, operation="nope")
        check("bad operation -> 400", post(url, bad_op).status_code == 400)
        dup = propose_body("eval-3", jwk1, [dossier(1), dossier(1)])
        check("duplicate dossierId -> 400", post(url, dup).status_code == 400)
        check("malformed JSON -> 400", post(url, "{not json").status_code == 400)

        def commit_body(eid, digest, receipts):
            return {"profile": PROFILE, "operation": "commit", "evaluationId": eid,
                    "inputDigest": digest, "receipts": receipts}

        props = j["proposals"]
        flags = [i % 2 == 0 for i in range(len(props))]
        good = make_receipts(sk1, "eval-1", j["inputDigest"], props, flags)

        evil_sk, _ = new_key()
        forged = make_receipts(evil_sk, "eval-1", j["inputDigest"], props[:1], [True]) + good[1:]
        check("one forged signature -> 400", post(url, commit_body("eval-1", j["inputDigest"], forged)).status_code == 400)
        moved = [dict(good[0], dossierId=good[1]["dossierId"])] + good[1:]
        check("moved receipt -> 400", post(url, commit_body("eval-1", j["inputDigest"], moved)).status_code == 400)
        check("unknown evaluation commit -> 404",
              post(url, commit_body("nope", j["inputDigest"], good)).status_code == 404)

        cb = commit_body("eval-1", j["inputDigest"], good)
        rc = post(url, cb); jc = rc.json()
        check("valid commit -> completed", rc.status_code == 200 and jc["status"] == "completed")
        check("executed/rejected follows accepted",
              [o["status"] for o in jc["outcomes"]] == ["executed" if f else "rejected" for f in flags])
        check("commit replay byte-identical", post(url, cb).content == rc.content)
    finally:
        srv.terminate()
    print(f"\n{sum(results)}/{len(results)} passed")
    sys.exit(0 if all(results) else 1)


if __name__ == "__main__":
    main()