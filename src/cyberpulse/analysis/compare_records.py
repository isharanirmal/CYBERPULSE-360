
from pathlib import Path
import pandas as pd

PROJECT_DIR = Path(__file__).resolve().parents[3]

RAW_FILE = (
    PROJECT_DIR / "data" / "raw" / "eurepoc"
    / "eurepoc_global_dataset_1_3.csv"
)

CLEAN_FILE = (
    PROJECT_DIR / "data" / "processed"
    / "eurepoc_incidents_cleaned.csv"
)

raw = pd.read_csv(
    RAW_FILE,
    encoding="utf-8-sig",
    low_memory=False,
    dtype={"incident_id": "string"}
)

clean = pd.read_csv(
    CLEAN_FILE,
    encoding="utf-8-sig",
    low_memory=False,
    dtype={"incident_id": "string"}
)

for label, df in [("RAW", raw), ("CLEANED", clean)]:
    print(f"\n--- {label} DATA ---")

    record = df[df["incident_id"] == "2954"]

    print("Matching rows:", len(record))

    if not record.empty:
        print(record[
            ["incident_id", "name", "incident_type", "initiator_country"]
        ].to_string(index=False))

print("\n--- INCIDENT TYPE CHECK ---")

bad = clean[
    clean["incident_type"].astype("string").eq("12599")
]

print("Rows with incident_type 12599:", len(bad))

if not bad.empty:
    print(bad[
        ["incident_id", "name", "incident_type", "initiator_country"]
    ].to_string(index=False))
