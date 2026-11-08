
from pathlib import Path
import csv

PROJECT_DIR = Path(__file__).resolve().parents[3]

RAW_FILE = (
    PROJECT_DIR / "data" / "raw" / "eurepoc"
    / "eurepoc_global_dataset_1_3.csv"
)

with open(RAW_FILE, "r", encoding="utf-8-sig", newline="") as file:

    reader = csv.DictReader(file)

    print("Expected columns:", len(reader.fieldnames))

    for row in reader:
        if any("UNC4841" in str(v) for v in row.values()):

            print("\nUNC4841 RECORD FOUND")

            important_fields = [
                "incident_id",
                "name",
                "incident_type",
                "start_date",
                "description",
                "initiator_country"
            ]

            for field in important_fields:
                print(f"{field}: {row.get(field)}")

            break
