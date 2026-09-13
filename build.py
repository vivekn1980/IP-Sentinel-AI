"""Build script compiling IP Sentinel AI into a single portable Windows EXE using PyInstaller."""

import os
import shutil
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent

def clean_previous_builds():
    print("Cleaning build, dist, and cache artifacts...")
    for folder in ["build", "dist", ".pytest_cache"]:
        p = PROJECT_ROOT / folder
        if p.exists():
            shutil.rmtree(p, ignore_errors=True)
            print(f"  Removed {p}")

def run_tests():
    print("\nRunning automated tests before packaging...")
    pytest_bin = PROJECT_ROOT / ".venv" / "Scripts" / "pytest.exe"
    cmd = [str(pytest_bin)] if pytest_bin.exists() else [sys.executable, "-m", "pytest"]
    res = subprocess.run(cmd, cwd=str(PROJECT_ROOT))
    if res.returncode != 0:
        print("[FAIL] Build aborted due to failing unit tests!")
        sys.exit(1)
    print("[SUCCESS] All unit tests passed.")

def build_exe():
    print("\nCompiling portable single-file Windows EXE with PyInstaller...")
    pyinstaller_bin = PROJECT_ROOT / ".venv" / "Scripts" / "pyinstaller.exe"
    cmd = [
        str(pyinstaller_bin) if pyinstaller_bin.exists() else "pyinstaller",
        "--clean",
        "--noconfirm",
        "pyinstaller.spec",
    ]
    res = subprocess.run(cmd, cwd=str(PROJECT_ROOT))
    if res.returncode != 0:
        print("[FAIL] PyInstaller compilation failed!")
        sys.exit(1)

    exe_path = PROJECT_ROOT / "dist" / "IP-Sentinel-AI.exe"
    if exe_path.exists():
        size_mb = exe_path.stat().st_size / (1024 * 1024)
        print(f"\n[SUCCESS] Portable Windows EXE created successfully!")
        print(f"   Binary Location : {exe_path}")
        print(f"   Executable Size : {size_mb:.2f} MB")
    else:
        print("[FAIL] Compiled executable not found at expected path dist/IP-Sentinel-AI.exe")
        sys.exit(1)

if __name__ == "__main__":
    clean_previous_builds()
    run_tests()
    build_exe()
