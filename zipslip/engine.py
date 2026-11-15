from __future__ import annotations
from typing import Any

def inspect_entry(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "archive": obj.get("archive"),
        "entry": obj.get("entry"),
        "target_root": obj.get("target_root"),
        "size": obj.get("size"),
        "mode": obj.get("mode"),
        "nonce": obj.get("nonce"),
    }

def admit_entry(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "entry": obj.get("entry")}
