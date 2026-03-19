#!/usr/bin/env python3
"""Build script - compiles the app into a portable executable using PyInstaller.

Usage:
    python build.py              Build one-file executable
    python build.py --onedir     Build one-directory bundle
    python build.py --clean      Remove build artifacts
"""

import subprocess
import sys
import os
import shutil
import platform

APP_NAME = "PortScanner"
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
MAIN_SCRIPT = os.path.join(SCRIPT_DIR, "main.py")
SPEC_FILE = os.path.join(SCRIPT_DIR, f"{APP_NAME}.spec")
DIST_DIR = SCRIPT_DIR
BUILD_DIR = os.path.join(SCRIPT_DIR, "build")


def check_pyinstaller():
    try:
        import PyInstaller
        print(f"[OK] PyInstaller {PyInstaller.__version__} found.")
        return True
    except ImportError:
        print("[ERROR] PyInstaller is not installed.")
        print("Install it with:  pip install pyinstaller")
        return False


def clean_build_artifacts():
    for dirname in ("build", "dist", "__pycache__"):
        path = os.path.join(SCRIPT_DIR, dirname)
        if os.path.exists(path):
            shutil.rmtree(path)
            print(f"[CLEAN] Removed {dirname}/")

    for subdir in ("core", "gui"):
        cache = os.path.join(SCRIPT_DIR, subdir, "__pycache__")
        if os.path.exists(cache):
            shutil.rmtree(cache)
            print(f"[CLEAN] Removed {subdir}/__pycache__/")

    if os.path.exists(SPEC_FILE):
        os.remove(SPEC_FILE)
        print(f"[CLEAN] Removed {APP_NAME}.spec")


def build(onedir=False):
    mode = "--onedir" if onedir else "--onefile"
    mode_label = "one-directory bundle" if onedir else "single-file executable"

    print(f"\n{'=' * 60}")
    print(f"  Building {APP_NAME} as {mode_label}")
    print(f"  Platform: {platform.system()} {platform.machine()}")
    print(f"{'=' * 60}\n")

    temp_dist = os.path.join(SCRIPT_DIR, "dist")

    cmd = [
        sys.executable, "-m", "PyInstaller",
        mode,
        "--name", APP_NAME,
        "--windowed",
        "--hidden-import", "core",
        "--hidden-import", "core.scanner",
        "--hidden-import", "gui",
        "--hidden-import", "gui.app",
        "--exclude-module", "matplotlib",
        "--exclude-module", "numpy",
        "--exclude-module", "scipy",
        "--exclude-module", "pandas",
        "--exclude-module", "PIL",
        "--exclude-module", "cv2",
        "--exclude-module", "torch",
        "--exclude-module", "tensorflow",
        "--distpath", temp_dist,
        "--workpath", BUILD_DIR,
        "--specpath", SCRIPT_DIR,
        MAIN_SCRIPT,
    ]

    print("Running PyInstaller...")
    result = subprocess.run(cmd, cwd=SCRIPT_DIR)

    if result.returncode != 0:
        print(f"\n[ERROR] Build failed with exit code {result.returncode}")
        sys.exit(1)

    # Move binary to App/PortScanner/ and clean up
    ext = ".exe" if platform.system() == "Windows" else ""
    src_binary = os.path.join(temp_dist, APP_NAME + ext)
    dst_binary = os.path.join(DIST_DIR, APP_NAME + ext)

    if os.path.exists(src_binary):
        shutil.move(src_binary, dst_binary)

    for path in (temp_dist, BUILD_DIR):
        if os.path.exists(path):
            shutil.rmtree(path)
    if os.path.exists(SPEC_FILE):
        os.remove(SPEC_FILE)

    print(f"\n{'=' * 60}")
    print(f"  BUILD SUCCESSFUL")
    print(f"  Binary: {dst_binary}")
    print(f"  Build artifacts cleaned automatically.")
    print(f"{'=' * 60}")
    print(f"\nTo run: use PortScannerPortable.sh (Linux)")
    print(f"or PortScannerPortable.bat (Windows)")
    print(f"from the PortScannerPortable/ root folder.")


if __name__ == "__main__":
    args = sys.argv[1:]

    if "--clean" in args:
        clean_build_artifacts()
        if len(args) == 1:
            sys.exit(0)

    if not check_pyinstaller():
        sys.exit(1)

    build(onedir="--onedir" in args)
    print("\nDone.")
