import os
import subprocess
import sys

def main():
    print("=" * 60)
    print("   AS Inspect — Understand applications with evidence.")
    print("   Developed by Abu Safyan")
    print("=" * 60)
    print()

    # 1. Ensure required dependencies are installed
    print("[*] Checking dependencies...")
    for pkg in ["pefile", "pytest"]:
        try:
            __import__(pkg)
            print(f" [+] {pkg} is already installed.")
        except ImportError:
            print(f" [*] Installing missing package: {pkg}...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", pkg])
            print(f" [+] {pkg} installed successfully.")

    print()
    print("[+] AS Inspect environment is 100% ready!")
    print()
    print("Quick CLI Usage:")
    print("  python apps/cli/as_inspect_cli.py analyze C:\\Windows\\System32\\notepad.exe")
    print("  python apps/cli/as_inspect_cli.py hash target.exe")
    print("  python apps/cli/as_inspect_cli.py detect target.exe")
    print()

if __name__ == "__main__":
    main()
