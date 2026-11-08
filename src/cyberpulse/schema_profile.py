
from pathlib import Path
import pandas as pd

PROJECT_DIR = Path(__file__).resolve().parents[2]

DATA_FILE = (
    PROJECT_DIR
    / "data"
    / "raw"
    / "eurepoc"
    / "eurepoc_global_dataset_1_3.csv"
)

KEY_COLUMNS = [
    "incident_id",
    "name",
    "start_date",
    "end_date",
    "incident_type",
    "receiver_country",
    "initiator_country",
    "mitre_initial_access",
    "mitre_impact",
    "data_theft",
    "disruption",
    "weighted_intensity",
    "economic_impact",
    "source_url",
]

def main():
    print("=" * 65)
    print("CYBERPULSE 360 - SCHEMA PROFILING")
    print("=" * 65)

    df = pd.read_csv(
        DATA_FILE,
        encoding="utf-8-sig",
        low_memory=False
    )

    for column in KEY_COLUMNS:
        if column not in df.columns:
            print(f"\n[NOT FOUND] {column}")
            continue

        print("\n" + "-" * 65)
        print(f"COLUMN: {column}")
        print(f"DATA TYPE: {df[column].dtype}")
        print(f"MISSING: {df[column].isna().sum()}")

        print("\nTOP 10 VALUES:")
        print(
            df[column]
            .fillna("[EMPTY]")
            .value_counts()
            .head(10)
            .to_string()
        )

        if column in [
            "receiver_country",
            "initiator_country",
            "mitre_initial_access",
            "mitre_impact",
        ]:
            semicolon_rows = (
                df[column]
                .fillna("")
                .astype(str)
                .str.contains(";", regex=False)
                .sum()
            )
            print(f"\nRows containing multiple values: {semicolon_rows}")

    print("\n" + "=" * 65)
    print("SCHEMA PROFILING COMPLETED")
    print("=" * 65)


if __name__ == "__main__":
    main()
