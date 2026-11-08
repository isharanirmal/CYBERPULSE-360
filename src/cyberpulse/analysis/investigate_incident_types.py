
from pathlib import Path
import pandas as pd

PROJECT_DIR = Path(__file__).resolve().parents[3]

DATA_FILE = (
    PROJECT_DIR / "data" / "processed"
    / "eurepoc_incidents_cleaned.csv"
)

df = pd.read_csv(
    DATA_FILE,
    encoding="utf-8-sig",
    low_memory=False,
    dtype={"incident_id": "string"}
)

suspect_values = ["12599", "Not available"]

for value in suspect_values:
    print("\n" + "=" * 60)
    print("INVESTIGATING:", value)
    print("=" * 60)

    rows = df[
        df["incident_type"].astype("string").str.contains(
            value,
            regex=False,
            na=False
        )
    ]

    print("Matching records:", len(rows))

    columns_to_show = [
        "incident_id",
        "name",
        "incident_type",
        "start_date",
        "description"
    ]

    available_columns = [
        col for col in columns_to_show if col in df.columns
    ]

    print(
        rows[available_columns].to_string(
            index=False,
            max_colwidth=150
        )
    )
