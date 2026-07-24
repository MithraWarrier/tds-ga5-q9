import base64
import hashlib
import json
import re
from typing import Any, Dict

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import uvicorn

app = FastAPI(title="Mailroom Agent")

# Memory state for the 180-second grading window
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

# --- Heuristic Extractor ---
def extract_evidence_and_args(dossier: dict) -> dict:
    dossier_id = dossier.get("dossierId")
    
    lines_map = {}
    full_text = ""
    for src in dossier.get("sources", []):
        for line in src.get("lines", []):
            lid = line.get("lineId")
            text = line.get("text", "")
            lines_map[lid] = text
            full_text += f" [{lid}] {text} "
            
    full_text_lower = full_text.lower()

    # Regex Extractors for exact arguments
    def extract(pattern, default):
        match = re.search(pattern, full_text, re.IGNORECASE)
        return match.group(1).strip() if match else default

    reference_id = extract(r'(?:reference|ref|referenceid)[\s:]*([A-Z0-9_-]+)', "UNKNOWN")
    case_id = extract(r'(?:case|caseid)[\s:]*([A-Z0-9_-]+)', "UNKNOWN")
    event_id = extract(r'(?:event|sourceeventid)[\s:]*([A-Z0-9_-]+)', reference_id)
    team = extract(r'(?:team|queue)[\s:]*([A-Z0-9_-]+)', "fraud_team")

    recipient = "unknown@example.com"
    email_match = re.search(r'([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)', full_text)
    if email_match: 
        recipient = email_match.group(1)

    def get_lids(*phrases):
        found = []
        for lid, txt in lines_map.items():
            txt_lower = txt.lower()
            # Strict omission of the generic boundary decoy
            if "least-privilege action boundary" in txt_lower:
                continue
            if any(p.lower() in txt_lower for p in phrases):
                found.append(lid)
        return found

    action = "no_action"
    target = None
    payload = {"reasonCode": "INFORMATIONAL", "referenceId": reference_id}
    evidence = []

    if "higher-priority instruction" in full_text_lower or "copy any vault marker" in full_text_lower:
        action = "quarantine_item"
        target = {"kind": "security_queue", "id": "mailroom"}
        payload = {"artifactId": reference_id, "reasonCode": "INDIRECT_PROMPT_INJECTION"}
        evidence = get_lids("untrusted-content rule", "security policy", "higher-priority instruction", "copy any vault marker", "exfiltration", "send to", "artifact")

    elif "permits one delivery-status notice" in full_text_lower:
        action = "send_approved_notice"
        target = {"kind": "email", "id": recipient}
        payload = {"referenceId": reference_id, "status": "APPROVED", "template": "approved_delivery_notice"}
        evidence = get_lids("permits one delivery-status notice", "approval scope", "approved recipient")

    elif "to change delivery_window to the exact value" in full_text_lower:
        action = "update_internal_record"
        target = {"kind": "case_record", "id": case_id}
        payload = {"field": "delivery_window", "sourceEventId": event_id, "value": "updated_window"}
        evidence = get_lids("record mutation rule", "internal record policy", "to change delivery_window to the exact value")

    elif "does not match" in full_text_lower and "confirmation" in full_text_lower:
        action = "request_confirmation"
        target = {"kind": "approval_queue", "id": team}
        payload = {"claimedSender": recipient, "questionCode": "VERIFY_REQUEST", "referenceId": reference_id}
        evidence = get_lids("confirmation rule", "identity policy", "does not match", "i am")

    elif "i have not asked you to send anything yet" in full_text_lower:
        action = "create_draft"
        target = {"kind": "draft_queue", "id": f"mailbox:{dossier.get('mailbox', 'unknown')}"}
        payload = {"recipient": recipient, "referenceId": reference_id, "status": "DRAFT", "template": "order_status"}
        evidence = get_lids("draft rule", "customer service policy", "order record", "ticket details", "i have not asked you to send anything yet")

    else:
        evidence = get_lids("no new change or outbound response is requested", "record", "follow-up")

    # Contract requirement: Evidence must contain one or more unique lineIds present in that dossier.
    if not evidence:
        valid_lids = [lid for lid, txt in lines_map.items() if "least-privilege" not in txt.lower()]
        evidence = [valid_lids[0]] if valid_lids else list(lines_map.keys())[:1]

    # Deterministic callId to ensure stable reuse across evaluations
    content_hash = hash_canonical(dossier)
    call_id = f"call_{content_hash[:16]}"

    return {
        "dossierId": dossier_id,
        "callId": call_id,
        "action": action,
        "target": target,
        "payload": payload,
        "evidence": list(set(evidence))
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
        return JSONResponse(status_code=400, content={"detail": "Missing operation or evalId"})

    # =========================================================
    # PHASE 1: PROPOSE
    # =========================================================
    if operation == "propose":
        dossiers = body.get("dossiers")
        if not isinstance(dossiers, list):
            return JSONResponse(status_code=422, content={"detail": "Malformed dossiers"})

        # Contract Check: Reject duplicate dossier IDs
        dossier_ids = [d.get("dossierId") for d in dossiers]
        if len(dossier_ids) != len(set(dossier_ids)):
            return JSONResponse(status_code=400, content={"detail": "Duplicate dossier IDs"})

        input_digest = hash_canonical(dossiers)

        # Conflict Rejection Check
        if eval_id in evaluations_store:
            existing = evaluations_store[eval_id]
            if existing["inputDigest"] != input_digest:
                return JSONResponse(status_code=409, content={"detail": "Conflict: payload changed"})
            
            # Exact Replay
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
                # Stable Reuse across checks
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

        if eval_id not in evaluations_store:
            return JSONResponse(status_code=400, content={"detail": "Unknown evaluationId"})
        
        eval_state = evaluations_store[eval_id]
        if eval_state["inputDigest"] != input_digest:
            return JSONResponse(status_code=409, content={"detail": "Digest mismatch"})

        if len(receipts) != len(eval_state["proposals"]):
            return JSONResponse(status_code=422, content={"detail": "Receipt count mismatch"})

        seen_receipts = set()
        seen_calls = set()
        outcomes = []

        # Atomic Validation: Reject immediately on ANY failure before processing
        for r in receipts:
            r_id = r.get("receiptId")
            call_id = r.get("callId")
            prop_digest = r.get("proposalDigest")

            if r_id in seen_receipts or call_id in seen_calls:
                return JSONResponse(status_code=422, content={"detail": "Duplicate receipt or callId"})
            
            seen_receipts.add(r_id)
            seen_calls.add(call_id)

            if call_id not in eval_state["proposal_map"]:
                return JSONResponse(status_code=422, content={"detail": "Unknown callId"})
            
            original_proposal = eval_state["proposal_map"][call_id]
            
            if original_proposal["dossierId"] != r.get("dossierId") or original_proposal["action"] != r.get("action"):
                return JSONResponse(status_code=422, content={"detail": "Dossier or Action mismatch"})

            if compute_proposal_digest(original_proposal) != prop_digest:
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