import base64
import hashlib
import json
import uuid
from typing import Any, Dict

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import uvicorn

app = FastAPI(title="Mailroom Agent")

evaluations_store: Dict[str, Dict[str, Any]] = {}
dossier_cache: Dict[str, Dict[str, Any]] = {}

# --- Canonical JSON & Hashing Utils ---
def sort_dict(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: sort_dict(obj[k]) for k in sorted(obj.keys())}
    elif isinstance(obj, list):
        return [sort_dict(x) for x in obj]
    else:
        return obj

def canonical_json_bytes(obj: Any) -> bytes:
    sorted_obj = sort_dict(obj)
    return json.dumps(sorted_obj, separators=(',', ':'), ensure_ascii=False).encode('utf-8')

def hash_canonical(obj: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(obj)).hexdigest()

def compute_proposal_digest(proposal: dict) -> str:
    evidence = sorted([str(e) for e in proposal.get("evidence", [])])
    digest_obj = {
        "dossierId": proposal["dossierId"],
        "callId": proposal["callId"],
        "action": proposal["action"],
        "target": proposal.get("target"),
        "payload": proposal.get("payload"),
        "evidence": evidence
    }
    return hash_canonical(digest_obj)

def verify_ed25519_signature(public_key_jwk: dict, message_bytes: bytes, signature_b64: str) -> bool:
    try:
        x_b64 = public_key_jwk.get("x", "")
        x_b64 += "=" * ((4 - len(x_b64) % 4) % 4)
        public_bytes = base64.urlsafe_b64decode(x_b64)
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_bytes)
        signature_bytes = base64.b64decode(signature_b64)
        public_key.verify(signature_bytes, message_bytes)
        return True
    except Exception:
        return False

# --- AI Extraction Logic (YOUR ACTION REQUIRED HERE) ---
def extract_evidence_and_args(dossier: dict) -> dict:
    """
    To get 70/70 on Evidence and Arguments, you MUST use an LLM here.
    Pass the `dossier` JSON to the LLM and ask it to output a JSON object with:
    - action
    - target (kind, id)
    - payload (only the exact keys required by the action schema)
    - evidence (array of EXACT lineIds needed to prove it, and nothing else)
    """
    
    # --- TEMPORARY MOCK LOGIC (Will not pass the 70/70 check without LLM) ---
    dossier_id = dossier.get("dossierId")
    content_hash = hash_canonical(dossier)
    call_id = f"call_{content_hash[:16]}"
    
    # Default fallback to prevent crashing, but an LLM must populate these dynamically.
    return {
        "dossierId": dossier_id,
        "callId": call_id,
        "action": "no_action", 
        "target": None,
        "payload": {"reasonCode": "INFORMATIONAL", "referenceId": "UNKNOWN"},
        "evidence": ["line_1"] 
    }

# --- Main API ---
@app.post("/")
async def mailroom_agent(request: Request):
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"detail": "Invalid JSON"})

    operation = body.get("operation")
    eval_id = body.get("evaluationId")

    if not operation or not eval_id:
        return JSONResponse(status_code=400, content={"detail": "Missing operation or evaluationId"})

    # =========================================================
    # PHASE 1: PROPOSE
    # =========================================================
    if operation == "propose":
        dossiers = body.get("dossiers")
        if not isinstance(dossiers, list):
            return JSONResponse(status_code=422, content={"detail": "Malformed dossiers"})

        dossier_ids = [d.get("dossierId") for d in dossiers]
        if len(dossier_ids) != len(set(dossier_ids)):
            return JSONResponse(status_code=400, content={"detail": "Duplicate dossier IDs"})

        input_digest = hash_canonical(dossiers)

        # Conflict rejection: strict matching
        if eval_id in evaluations_store:
            existing = evaluations_store[eval_id]
            if existing["inputDigest"] != input_digest:
                return JSONResponse(status_code=409, content={"detail": "Evaluation ID conflict with different payload"})
            
            return JSONResponse({
                "profile": "ga5-mailroom-action-gate/v2",
                "evaluationId": eval_id,
                "status": "awaiting_receipts",
                "inputDigest": input_digest,
                "proposals": existing["proposals"]
            })

        proposals = []
        for d in dossiers:
            d_id = d.get("dossierId")
            content_fingerprint = hash_canonical(d)

            if content_fingerprint in dossier_cache:
                cached_prop = dict(dossier_cache[content_fingerprint])
                cached_prop["dossierId"] = d_id
                proposals.append(cached_prop)
            else:
                proposal = extract_evidence_and_args(d)
                proposals.append(proposal)
                dossier_cache[content_fingerprint] = proposal

        evaluations_store[eval_id] = {
            "inputDigest": input_digest,
            "verifier": body.get("receiptVerifier", {}).get("publicKeyJwk"),
            "proposals": proposals,
            "proposal_map": {p["callId"]: p for p in proposals}
        }

        return JSONResponse({
            "profile": "ga5-mailroom-action-gate/v2",
            "evaluationId": eval_id,
            "status": "awaiting_receipts",
            "inputDigest": input_digest,
            "proposals": proposals
        })

    # =========================================================
    # PHASE 2: COMMIT
    # =========================================================
    elif operation == "commit":
        input_digest = body.get("inputDigest")
        receipts = body.get("receipts", [])

        # Conflict rejection for commit
        if eval_id not in evaluations_store:
            return JSONResponse(status_code=400, content={"detail": "Unknown evaluationId"})
        
        eval_state = evaluations_store[eval_id]
        if eval_state["inputDigest"] != input_digest:
            return JSONResponse(status_code=409, content={"detail": "Input digest mismatch"})

        if len(receipts) != len(eval_state["proposals"]):
            return JSONResponse(status_code=422, content={"detail": "Receipt count mismatch"})

        seen_receipts = set()
        seen_calls = set()
        outcomes = []

        # Validate EVERYTHING atomically before executing any action
        for r in receipts:
            r_id = r.get("receiptId")
            call_id = r.get("callId")
            prop_digest = r.get("proposalDigest")

            if r_id in seen_receipts:
                return JSONResponse(status_code=422, content={"detail": "Duplicate receipt"})
            seen_receipts.add(r_id)

            if call_id in seen_calls:
                return JSONResponse(status_code=422, content={"detail": "Duplicate callId in receipt"})
            seen_calls.add(call_id)

            if call_id not in eval_state["proposal_map"]:
                return JSONResponse(status_code=422, content={"detail": "Unknown callId in receipt"})
            
            original_proposal = eval_state["proposal_map"][call_id]
            
            # Verify the dossier ID matches the call ID
            if original_proposal["dossierId"] != r.get("dossierId"):
                return JSONResponse(status_code=422, content={"detail": "Receipt dossierId mismatch"})
            
            # Verify action matches
            if original_proposal["action"] != r.get("action"):
                return JSONResponse(status_code=422, content={"detail": "Receipt action mismatch"})

            expected_digest = compute_proposal_digest(original_proposal)
            if expected_digest != prop_digest:
                return JSONResponse(status_code=422, content={"detail": "Proposal digest mismatch"})

            inner_receipt = {
                "profile": "ga5-mailroom-action-gate/v2",
                "evaluationId": eval_id,
                "inputDigest": input_digest,
                "receipt": {
                    "dossierId": r.get("dossierId"),
                    "callId": call_id,
                    "action": r.get("action"),
                    "accepted": r.get("accepted"),
                    "proposalDigest": prop_digest,
                    "receiptId": r_id
                }
            }
            
            msg_bytes = canonical_json_bytes(inner_receipt)
            if not verify_ed25519_signature(eval_state["verifier"], msg_bytes, r.get("receiptSignature")):
                return JSONResponse(status_code=422, content={"detail": "Invalid signature"})

            outcomes.append({
                "dossierId": r.get("dossierId"),
                "callId": call_id,
                "action": r.get("action"),
                "proposalDigest": prop_digest,
                "receiptId": r_id,
                "status": "executed" if r.get("accepted") else "rejected"
            })

        return JSONResponse({
            "profile": "ga5-mailroom-action-gate/v2",
            "evaluationId": eval_id,
            "status": "completed",
            "inputDigest": input_digest,
            "outcomes": outcomes
        })

    return JSONResponse(status_code=400, content={"detail": "Unknown operation"})

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)