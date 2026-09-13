"""Clean build script removing build folders, dist output, and cached python bytecode."""

import shutil
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent

def clean():
    print("Performing full workspace cleanup...")
    targets = ["build", "dist", ".pytest_cache", "*.egg-info"]
    for pattern in targets:
        for p in PROJECT_ROOT.glob(pattern):
            if p.is_dir():
                shutil.rmtree(p, ignore_errors=True)
                print(f"  Deleted directory: {p}")
            elif p.is_file():
                p.unlink(missing_ok=True)
                print(f"  Deleted file: {p}")

    # Remove __pycache__ directories recursively
    for pycache in PROJECT_ROOT.rglob("__pycache__"):
        shutil.rmtree(pycache, ignore_errors=True)
        print(f"  Deleted __pycache__: {pycache}")

    print("Cleanup complete.")

if __name__ == "__main__":
    clean()
