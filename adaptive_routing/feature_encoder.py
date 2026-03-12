from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import hashlib
from typing import Any, Dict


def _safe_int(x: Any, default: int = 0) -> int:
    try:
        return int(x)
    except Exception:
        return default


def _safe_float(x: Any, default: float = 0.0) -> float:
    try:
        return float(x)
    except Exception:
        return default


def _ip_last_octet(ip: Any) -> int:
    """
    Convert '192.168.1.14' -> 14.
    If parsing fails, return 0.
    """
    try:
        s = str(ip).strip()
        if not s:
            return 0
        parts = s.split(".")
        return int(parts[-1])
    except Exception:
        return 0


def _parse_timestamp(ts: Any) -> datetime | None:
    s = str(ts).strip()
    if not s:
        return None
    # dataset uses "YYYY-mm-dd HH:MM:SS"
    try:
        return datetime.fromisoformat(s)
    except Exception:
        return None


def _stable_hash_to_int(value: Any, mod: int) -> int:
    """
    Deterministic hashing for categorical features.

    IMPORTANT:
    - Do NOT use Python built-in `hash()` here because it is salted per process
      (PYTHONHASHSEED), causing non-reproducible encodings across runs.
    """
    s = str(value)
    digest = hashlib.sha256(s.encode("utf-8")).digest()
    n = int.from_bytes(digest[:8], byteorder="big", signed=False)
    return int(n % int(mod))


@dataclass
class SimpleRecordEncoder:
    """
    Turn a raw internal-name record into a numeric record, but keep the SAME keys.

    Why:
    - Feature-sensitivity rules are key-name based (e.g., 'ip_address', 'location', 'timestamp').
    - MixedProtectionPipeline expects those same keys to decide which fields go to HE.
    - HE encryptors (Paillier / CKKS) require numeric inputs, so we encode values.
    """

    # For categorical values, we do deterministic hashing to small-ish integers.
    # (This is a PoC-friendly stand-in for fitting LabelEncoders on the dataset.)
    hash_mod: int = 10_000

    def encode(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        out: Dict[str, Any] = {}

        for k, v in raw.items():
            if k in ("session_duration", "failed_attempts", "behavioral_score", "anomaly"):
                # numeric features (keep them numeric)
                out[k] = _safe_float(v) if k != "failed_attempts" else _safe_int(v)
                continue

            if k == "user_id":
                # keep as numeric if possible; otherwise hash
                if isinstance(v, (int, float)) or (isinstance(v, str) and v.strip().isdigit()):
                    out[k] = _safe_int(v)
                else:
                    out[k] = _stable_hash_to_int(v, self.hash_mod)
                continue

            if k == "ip_address":
                out[k] = _ip_last_octet(v)
                continue

            if k == "timestamp":
                dt = _parse_timestamp(v)
                # encode to hour-of-day (0-23) for a bounded numeric representation
                out[k] = dt.hour if dt else 0
                continue

            if k in ("location", "device_type", "login_status"):
                out[k] = _stable_hash_to_int(v, self.hash_mod)
                continue

            # default: try float, otherwise hash
            try:
                out[k] = float(v)
            except Exception:
                out[k] = _stable_hash_to_int(v, self.hash_mod)

        return out

