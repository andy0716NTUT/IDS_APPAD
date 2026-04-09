from __future__ import annotations

import argparse
import subprocess
import sys
import time
import shutil
from pathlib import Path

from pipeline.appad_pipeline import cli_main


ROOT = Path(__file__).resolve().parent
FRONTEND_DIR = ROOT / "frontend"


def _run_web_stack() -> int:
    if not FRONTEND_DIR.exists():
        print("frontend directory not found.")
        return 1

    print("Starting backend API and frontend website...")
    print("Press Ctrl+C to stop both services.")

    backend_cmd = [sys.executable, "backend_api.py"]

    npm_exec = shutil.which("npm") or shutil.which("npm.cmd")
    if not npm_exec:
        print("npm not found in PATH. Please install Node.js or add npm to PATH.")
        return 1

    frontend_cmd = [npm_exec, "run", "web"]

    backend_proc = subprocess.Popen(backend_cmd, cwd=str(FRONTEND_DIR))
    frontend_proc = None

    try:
        # Let backend bind port before opening web UI.
        time.sleep(1.0)
        frontend_proc = subprocess.Popen(frontend_cmd, cwd=str(FRONTEND_DIR))

        frontend_code = frontend_proc.wait()
        return int(frontend_code)
    except KeyboardInterrupt:
        print("\nStopping web services...")
        return 0
    finally:
        if frontend_proc and frontend_proc.poll() is None:
            frontend_proc.terminate()
        if backend_proc.poll() is None:
            backend_proc.terminate()


def _parse_args(argv: list[str] | None) -> tuple[argparse.Namespace, list[str]]:
    parser = argparse.ArgumentParser(
        description="Entry point: launch web UI by default, or run pipeline with --pipeline"
    )
    parser.add_argument(
        "--pipeline",
        action="store_true",
        help="Run APPAD pipeline CLI instead of launching frontend website.",
    )
    return parser.parse_known_args(argv)


if __name__ == "__main__":
    args, remaining = _parse_args(sys.argv[1:])
    if args.pipeline:
        cli_main(remaining)
    else:
        raise SystemExit(_run_web_stack())
