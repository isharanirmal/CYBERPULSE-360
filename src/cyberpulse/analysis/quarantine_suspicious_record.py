
import pandas as pd
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parents[3]

INPUT_FILE = (
    PROJECT_DIR / "data" / "processed"
    / "eurepoc_incidents_cleaned.csv"
)

INTERIM_DIR = PROJECT_DIR / "data" / "interim"
OUTPUT_DIR = PROJECT_DIR / "data" / "processed"

INTERIM_DIR.mkdir(parents=True, exist_ok=True)

df = pd.read_csv(
    INPUT_FILE,
    dtype={"incident_id": "string"},
    low_memory=False
)

# Identify the suspicious record
mask = (
    df["incident_type"]
    .astype("string")
    .str.strip()
    .eq("12599")
    .fillna(False)
)

suspicious = df.loc[mask].copy()
valid = df.loc[~mask].copy()

if suspicious.empty:
    raise ValueError("No suspicious records found. Check the source data.")

suspicious["quality_flag"] = "suspected_column_misalignment"

# Save suspicious records separately
suspicious.to_csv(
    INTERIM_DIR / "quarantined_records.csv",
    index=False
)

# Save remaining records for analysis
valid.to_csv(
    OUTPUT_DIR / "eurepoc_incidents_analysis_ready.csv",
    index=False
)

print("Original records:", len(df))
print("Quarantined records:", len(suspicious))
print("Analysis-ready records:", len(valid))

print("\nFiles saved successfully.")
