from pathlib import Path
from datetime import datetime


PROJECT_NAME = "CYBERPULSE 360"

BASE_DIR = Path(__file__).resolve().parents[2]

REQUIRED_FOLDERS = [
    "data/raw",
    "data/interim",
    "data/processed",
    "data/external",
    "notebooks",
    "reports",
    "documentation",
]


def display_banner():
    print("=" * 55)
    print("       CYBERPULSE 360")
    print(" Global Cyber Threat Intelligence Platform")
    print("=" * 55)


def check_project_folders():
    print("\n[PROJECT STRUCTURE CHECK]")

    for folder in REQUIRED_FOLDERS:
        folder_path = BASE_DIR / folder

        if folder_path.exists():
            print(f"[OK] {folder}")
        else:
            print(f"[MISSING] {folder}")


def display_system_info():
    print("\n[PROJECT INFORMATION]")
    print(f"Project : {PROJECT_NAME}")
    print(f"Date    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Location: {BASE_DIR}")


def main():
    display_banner()
    display_system_info()
    check_project_folders()

    print("\nCYBERPULSE 360 is ready for development!")


if __name__ == "__main__":
    main()