
from pathlib import Path
import json
import pandas as pd

# CYBERPULSE 360 - EDA OVERVIEW

PROJECT_DIR = Path(__file__).resolve().parents[3]

DATA_FILE = (
    PROJECT_DIR / "data" / "processed"
    / "eurepoc_incidents_analysis_ready.csv"
)

OUTPUT_DIR = PROJECT_DIR / "reports" / "findings"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def main():
    print("=" * 65)
    print("CYBERPULSE 360 - EXPLORATORY DATA ANALYSIS")
    print("=" * 65)

    df = pd.read_csv(
        DATA_FILE,
        encoding="utf-8-sig",
        low_memory=False
    )

    print("\n[1] DATASET OVERVIEW")
    print("-" * 45)
    print("Rows:", len(df))
    print("Columns:", len(df.columns))
    print("Unique incident IDs:", df["incident_id"].nunique())

    print("\n[2] INCIDENTS BY YEAR")
    print("-" * 45)

    df["year"] = df["start_date_parsed"].str[:4]

    yearly = (
        df.dropna(subset=["start_date_parsed"])
        .assign(
            year=lambda x: pd.to_datetime(
                x["start_date_parsed"]
            ).dt.year
        )
        .groupby("year")
        .size()
        .reset_index(name="incident_count")
        .sort_values("year")
    )

    print(yearly.to_string(index=False))

    yearly.to_csv(
        OUTPUT_DIR / "incidents_by_year.csv",
        index=False
    )

    print("\n[3] TOP INCIDENT TYPES")
    print("-" * 45)

    incident_types = (
        df["incident_type"]
        .value_counts(dropna=False)
        .head(15)
    )

    print(incident_types.to_string())

    incident_types.rename_axis("incident_type").reset_index(
        name="count"
    ).to_csv(
        OUTPUT_DIR / "top_incident_types.csv",
        index=False
    )

    print("\n[4] WEIGHTED INTENSITY DISTRIBUTION")
    print("-" * 45)

    intensity = df["weighted_intensity_num"].value_counts(
        dropna=False
    ).sort_index()

    print(intensity.to_string())

    intensity.rename_axis("weighted_intensity").reset_index(
        name="incident_count"
    ).to_csv(
        OUTPUT_DIR / "intensity_distribution.csv",
        index=False
    )

    print("\n[5] ATTRIBUTION STATUS")
    print("-" * 45)

    attribution = (
        df["initiator_country"]
        .value_counts(dropna=False)
        .head(15)
    )

    print(attribution.to_string())

    print("\n[6] SUMMARY")
    print("-" * 45)

    summary = {
        "total_incidents": int(len(df)),
        "unique_incident_ids": int(
            df["incident_id"].nunique()
        ),
        "yearly_data_points": int(len(yearly)),
        "most_common_incident_type": str(
            df["incident_type"].mode().iloc[0]
        ),
        "average_weighted_intensity": float(
            df["weighted_intensity_num"].mean()
        ),
        "median_weighted_intensity": float(
            df["weighted_intensity_num"].median()
        ),
    }

    print(json.dumps(summary, indent=4))

    with open(
        OUTPUT_DIR / "eda_overview_summary.json",
        "w",
        encoding="utf-8"
    ) as file:
        json.dump(summary, file, indent=4)

    print("\nEDA OVERVIEW COMPLETED!")


if __name__ == "__main__":
    main()
