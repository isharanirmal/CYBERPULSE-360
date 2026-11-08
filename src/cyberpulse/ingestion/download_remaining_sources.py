
import requests
import hashlib
import json
import sys

from pathlib import Path
from datetime import datetime, timezone

PROJECT_DIR = Path(__file__).resolve().parents[3]
RAW_DIR = PROJECT_DIR / "data" / "raw"
REPORT_DIR = PROJECT_DIR / "reports" / "findings"

SOURCES = [
    {
        "name": "CISA KEV",
        "url": "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json",
        "file": "cisa_kev/known_exploited_vulnerabilities.json"
    },
    {
        "name": "MITRE ATT&CK Enterprise",
        "url": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json",
        "file": "mitre_attack/enterprise-attack.json"
    },
    {
        "name": "ThreatCluster Ransomware Victims",
        "url": "https://raw.githubusercontent.com/Jam0k/Threat-Intelligence-Datasets/main/ransomware-leak-site-victims/data.jsonl",
        "file": "ransomware/ransomware_leak_site_victims.jsonl"
    }
]


def download_source(source):

    destination = RAW_DIR / source["file"]
    destination.parent.mkdir(parents=True, exist_ok=True)

    temporary_file = destination.with_name(
        destination.name + ".part"
    )

    sha256 = hashlib.sha256()
    total_bytes = 0

    print(f"\nDownloading: {source['name']}")

    try:
        with requests.get(
            source["url"],
            stream=True,
            timeout=(20, 180),
            headers={"User-Agent": "CYBERPULSE-360"}
        ) as response:

            response.raise_for_status()

            with open(temporary_file, "wb") as file:

                for chunk in response.iter_content(
                    chunk_size=1024 * 1024
                ):
                    if chunk:
                        file.write(chunk)
                        sha256.update(chunk)
                        total_bytes += len(chunk)

        if total_bytes == 0:
            raise ValueError("Downloaded file is empty.")

        temporary_file.replace(destination)

        size_mb = total_bytes / (1024 * 1024)

        print(f"SUCCESS: {size_mb:.2f} MB")

        return {
            "name": source["name"],
            "url": source["url"],
            "file": source["file"],
            "size_bytes": total_bytes,
            "sha256": sha256.hexdigest(),
            "status": "success"
        }

    except Exception as error:

        if temporary_file.exists():
            temporary_file.unlink()

        print(f"FAILED: {error}")

        return {
            "name": source["name"],
            "url": source["url"],
            "status": "failed",
            "error": str(error)
        }


def main():

    print("=" * 65)
    print("CYBERPULSE 360 - REMAINING DATASET DOWNLOAD")
    print("=" * 65)

    results = []

    for source in SOURCES:
        results.append(download_source(source))

    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    manifest = {
        "project": "CYBERPULSE 360",
        "downloaded_at_utc": datetime.now(
            timezone.utc
        ).isoformat(),
        "sources": results
    }

    manifest_file = REPORT_DIR / "source_manifest.json"

    with open(manifest_file, "w", encoding="utf-8") as file:
        json.dump(
            manifest,
            file,
            indent=4,
            ensure_ascii=False
        )

    successful = sum(
        item["status"] == "success"
        for item in results
    )

    print("\n" + "=" * 65)
    print("DOWNLOAD SUMMARY")
    print("=" * 65)

    print(f"Successful: {successful}/3")
    print(f"Failed: {3 - successful}/3")
    print(f"Manifest: {manifest_file}")

    if successful == 3:
        print("\nALL REMAINING DATASETS DOWNLOADED!")
    else:
        print("\nSOME DOWNLOADS FAILED. Check the messages above.")
        sys.exit(1)


if __name__ == "__main__":
    main()
