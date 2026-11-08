
from pathlib import Path
import pandas as pd

PROJECT_DIR = Path(__file__).resolve().parents[3]

DATA_FILE = (
    PROJECT_DIR / "data" / "processed"
    / "eurepoc_incidents_analysis_ready.csv"
)

OUTPUT_DIR = PROJECT_DIR / "reports" / "findings"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def main():
    print("=" * 60)
    print("CYBERPULSE 360 - INCIDENT TYPE ANALYSIS")
    print("=" * 60)

    df = pd.read_csv(
        DATA_FILE,
        encoding="utf-8-sig",
        low_memory=False,
        dtype={"incident_id": "string"}
    )

    # Split only on semicolons.
    # Keep labels containing '&' intact.
    type_data = df[
        ["incident_id", "incident_type"]
    ].dropna(subset=["incident_type"]).copy()

    type_data["incident_type"] = (
        type_data["incident_type"].str.split(";")
    )

    type_data = type_data.explode("incident_type")

    type_data["incident_type"] = (
        type_data["incident_type"].str.strip()
    )

    type_data = type_data[
        type_data["incident_type"].ne("")
    ]

    # Count each category only once per incident.
    type_data = type_data.drop_duplicates(
        subset=["incident_id", "incident_type"]
    )

    counts = (
        type_data["incident_type"]
        .value_counts()
        .rename_axis("incident_type")
        .reset_index(name="incident_count")
    )

    print("\nINDIVIDUAL INCIDENT TYPE FREQUENCIES")
    print("-" * 50)
    print(counts.to_string(index=False))

    counts.to_csv(
        OUTPUT_DIR / "individual_incident_type_counts.csv",
        index=False,
        encoding="utf-8-sig"
    )

    print("\nTotal individual type categories:", len(counts))
    print("Total incident-category links:", len(type_data))

    print("\nSaved: individual_incident_type_counts.csv")
    print("\nINCIDENT TYPE ANALYSIS COMPLETED!")


if __name__ == "__main__":
    main()
