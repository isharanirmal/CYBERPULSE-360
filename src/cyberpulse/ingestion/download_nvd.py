
from pathlib import Path
from datetime import datetime
import requests

PROJECT_DIR = Path(__file__).resolve().parents[3]

RAW_DIR = PROJECT_DIR / "data" / "raw" / "nvd"
RAW_DIR.mkdir(parents=True, exist_ok=True)

BASE_URL = "https://nvd.nist.gov/feeds/json/cve/2.0"

START_YEAR = 2020
END_YEAR = datetime.now().year


def download_file(url, destination):
    if destination.exists() and destination.stat().st_size > 0:
        print(f"Already downloaded: {destination.name}")
        return

    temporary_file = destination.with_suffix(
        destination.suffix + ".part"
    )

    print(f"Downloading: {destination.name}")

    with requests.get(
        url,
        stream=True,
        timeout=(20, 120)
    ) as response:

        response.raise_for_status()

        with open(temporary_file, "wb") as file:
            for chunk in response.iter_content(
                chunk_size=1024 * 1024
            ):
                if chunk:
                    file.write(chunk)

    temporary_file.replace(destination)

    size_mb = destination.stat().st_size / (1024 * 1024)
    print(f"Downloaded: {size_mb:.2f} MB")


def main():
    print("=" * 55)
    print("CYBERPULSE 360 - NVD DATA DOWNLOADER")
    print("=" * 55)

    for year in range(START_YEAR, END_YEAR + 1):
        filename = f"nvdcve-2.0-{year}.json.gz"
        meta_filename = f"nvdcve-2.0-{year}.meta"

        try:
            download_file(
                f"{BASE_URL}/{meta_filename}",
                RAW_DIR / meta_filename
            )

            download_file(
                f"{BASE_URL}/{filename}",
                RAW_DIR / filename
            )

        except requests.RequestException as error:
            print(f"\nDownload failed for {year}: {error}")
            print("Run the script again to retry.")
            return

    print("\nNVD DOWNLOAD COMPLETED!")


if __name__ == "__main__":
    main()
