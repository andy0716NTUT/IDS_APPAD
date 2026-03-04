from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

from Week7_8.adaptive_router import RoutingConfig
from Week7_8.system import IDSSystem, IDSSystemConfig


COLUMN_MAPPING = {
    "User ID": "user_id",
    "Login Status": "login_status",
    "IP Address": "ip_address",
    "Location": "location",
    "Session Duration": "session_duration",
    "Failed Attempts": "failed_attempts",
    "Behavioral Score": "behavioral_score",
    "Timestamp": "timestamp",
    "Device Type": "device_type",
    "Anomaly": "anomaly",
}


def load_records(n: int = 8) -> list[dict]:
    base_dir = Path(__file__).resolve().parents[1]
    dataset_path = base_dir / "dataset" / "synthetic_web_auth_logs.csv"
    df = pd.read_csv(dataset_path).head(n)

    out: list[dict] = []
    for _, row in df.iterrows():
        rec = {}
        for csv_col, internal in COLUMN_MAPPING.items():
            if csv_col in row:
                rec[internal] = row[csv_col]
        out.append(rec)
    return out


def _to_jsonable(x):  # type: ignore[no-untyped-def]
    """
    Best-effort conversion for pandas/numpy scalars so json.dump() is stable.
    """
    # common numpy/pandas scalar pattern
    if hasattr(x, "item") and callable(x.item):
        try:
            return x.item()
        except Exception:
            pass

    # pandas Timestamp / datetime-like
    if hasattr(x, "isoformat") and callable(x.isoformat):
        try:
            return x.isoformat()
        except Exception:
            pass

    if isinstance(x, dict):
        return {str(k): _to_jsonable(v) for k, v in x.items()}
    if isinstance(x, (list, tuple)):
        return [_to_jsonable(v) for v in x]

    # JSON primitives
    if x is None or isinstance(x, (str, int, float, bool)):
        return x

    # fallback: stringify anything unexpected (shouldn't happen in this demo)
    return str(x)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Week7-8 Adaptive Routing Demo")
    parser.add_argument(
        "--output",
        default="Week7_8/demo_output.json",
        help="Path to write demo results as JSON (default: Week7_8/demo_output.json if relative).",
    )
    parser.add_argument("--n", type=int, default=8, help="Number of records to demo (default: 8).")
    args = parser.parse_args(argv)

    # Client holds the secret key, so encryptor lives here.
    # 在真實系統前提下：必須使用真正的 Paillier HE，沒有就直接報錯。
    try:
        from Week6.he_encryptor import PaillierEncryptor
    except ImportError as e:
        raise ImportError(
            "此 demo 以真實同態加密系統為前提，必須先安裝 `phe` 並使用 PaillierEncryptor。\n"
            "請先執行：pip install phe"
        ) from e

    encryptor = PaillierEncryptor()
    encryptor_name = "PaillierEncryptor(phe)"

    base_dir = Path(__file__).resolve().parents[1]
    out_path = Path(args.output)
    if not out_path.is_absolute():
        out_path = base_dir / out_path

    system = IDSSystem(
        IDSSystemConfig(
            routing=RoutingConfig(
                latency_budget_ms=120.0,
                network_rtt_ms=30.0,
                prefer_he_on_medium=True,
            ),
            decision_threshold=0.5,
        ),
        encryptor=encryptor,
    )

    records = load_records(n=int(args.n))

    print("\n=== Week7-8 Adaptive Routing Demo ===")
    print(f"Encryptor: {encryptor_name}")
    print("Router policy:")
    print(" - HIGH sensitivity -> mixed HE route")
    print(" - LOW sensitivity  -> plaintext route")
    print(" - MEDIUM sensitivity -> HE if within latency budget else plaintext")
    print()

    demo_results: list[dict] = []
    for i, rec in enumerate(records):
        result = system.process_event(rec)
        s = result["sensitivity"]

        print(f"[{i}] route={result['route']}, enable_he={result['enable_he']}, "
              f"level={s['sensitivity_level']}, risk={s['risk_score']}, "
              f"lat={result['latency_ms']}ms, est={result['latency_est_ms']}ms")
        print(f"    encrypted_keys={result['payload_summary']['encrypted_keys']}")
        print(f"    prob={result['prob']:.4f}, is_anomaly={result['is_anomaly']}, decrypted={result['decrypted']}")

        demo_results.append(
            {
                "index": i,
                "record": _to_jsonable(rec),
                # result is already designed to be JSON-safe (no ciphertexts),
                # but we still normalize numeric scalars for stability.
                "result": _to_jsonable(result),
            }
        )

    out_payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "encryptor": encryptor_name,
        "config": {
            "routing": {
                "latency_budget_ms": system.config.routing.latency_budget_ms,
                "network_rtt_ms": system.config.routing.network_rtt_ms,
                "prefer_he_on_medium": system.config.routing.prefer_he_on_medium,
            },
            "decision_threshold": system.config.decision_threshold,
        },
        "n": len(demo_results),
        "results": demo_results,
    }

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(out_payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\nWrote demo output JSON to: {out_path}")


if __name__ == "__main__":
    main()

