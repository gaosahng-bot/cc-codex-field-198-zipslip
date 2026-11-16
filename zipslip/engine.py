from __future__ import annotations
import base64
import hashlib
import hmac
from typing import Any

SIGNING_VERSION = "v1"


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


def _signing_input(obj: dict) -> str:
    return "|".join((
        SIGNING_VERSION,
        str(obj.get("kid")),
        str(obj.get("archive")),
        str(obj.get("entry")),
        str(obj.get("target_root")),
        str(obj.get("size")),
        str(obj.get("mode")),
        str(obj.get("iat")),
        str(obj.get("nonce")),
    ))


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def admit_entry(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    reasons: list[str] = []
    entry = obj.get("entry")
    archive = obj.get("archive")
    target_root = obj.get("target_root")
    mode = obj.get("mode")
    size = obj.get("size")
    kid = obj.get("kid")

    if not isinstance(entry, str) or any(
        token in entry for token in policy.get("entry_deny_substrings", [])
    ):
        reasons.append("entry_deny_substring")
    if policy.get("forbid_absolute_entry") and isinstance(entry, str) and entry.startswith("/"):
        reasons.append("entry_absolute")

    if policy.get("forbid_symlink_mode") and mode in policy.get("symlink_modes", []):
        reasons.append("symlink_mode")

    if target_root not in policy.get("allowed_roots", []):
        reasons.append("target_root_not_allowed")

    suffixes = policy.get("archive_suffixes", [])
    if not isinstance(archive, str) or not any(archive.endswith(s) for s in suffixes):
        reasons.append("archive_suffix_not_allowed")

    if not isinstance(size, int) or isinstance(size, bool) or size > policy.get("size_max"):
        reasons.append("size_exceeded")

    key = keys.get("keys", {}).get(kid)
    if not isinstance(key, dict):
        reasons.append("key_unknown")
    elif key.get("status") != "active":
        reasons.append("key_revoked")
    else:
        secret = bytes.fromhex(key["secret"])
        digest = hmac.new(secret, _signing_input(obj).encode("utf-8"), hashlib.sha256).digest()
        if not hmac.compare_digest(_b64url(digest), str(obj.get("sig"))):
            reasons.append("bad_signature")

    iat = obj.get("iat")
    skew = policy.get("clock_skew_seconds", 0)
    max_age = policy.get("max_age_seconds", 0)
    if not isinstance(iat, int) or isinstance(iat, bool) or iat > now_unix + skew or iat < now_unix - max_age:
        reasons.append("iat_out_of_window")

    nonce = obj.get("nonce")
    items = store.setdefault("items", {})
    if nonce in items:
        reasons.append("nonce_replayed")

    if reasons:
        return {"decision": "deny", "reason_codes": reasons, "entry": entry}

    items[nonce] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "entry": entry}
