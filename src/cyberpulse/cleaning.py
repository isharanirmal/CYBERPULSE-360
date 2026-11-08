
from pathlib import Path
import json
import pandas as pd

# CYBERPULSE 360 - CLEANING PIPELINE

PROJECT_DIR = Path(__file__).resolve().parents[2]

RAW_FILE = (
    PROJECT_DIR / "data" / "raw" / "eurepoc"
    / "eurepoc_global_dataset_1_3.csv"
)

OUTPUT_DIR = PROJECT_DIR / "data" / "processed"
REPORT_DIR = PROJECT_DIR / "reports" / "findings"

DATE_FORMATS = {
    "start_date": "%d.%m.%Y",
    "end_date": "%d.%m.%Y",
    "attribution_date": "%d.%m.%Y",
    "political_response_date": "%d.%m.%Y",
    "legal_response_date": "%m/%d/%Y",
    "added_to_db": "%m/%d/%Y",
    "updated_at": "%m/%d/%Y",
}

NUMERIC_COLUMNS = [
    "number_attributions",
    "number_political_responses",
    "number_legal_responses",
    "weighted_intensity",
    "unweighted_intensity",
    "impact_indicator_score",
]


def load_data():
    print("\n[1/5] Loading raw dataset...")

    if not RAW_FILE.exists():
        raise FileNotFoundError(f"File not found: {RAW_FILE}")

    df = pd.read_csv(
        RAW_FILE,
        encoding="utf-8-sig",
        low_memory=False,
        dtype={"incident_id": "string"}
    )

    print(f"Loaded {len(df):,} records.")
    return df


def clean_text(df):
    print("\n[2/5] Cleaning text columns...")

    text_columns = df.select_dtypes(
        include=["object", "string"]
    ).columns

    for column in text_columns:
        df[column] = df[column].astype("string").str.strip()

    # Convert empty or whitespace-only values to missing.
    df = df.replace(r"^\s*$", pd.NA, regex=True)

    # Intentionally preserve labels such as:
    # Unknown, Not attributed, Not available, none

    print("Text normalization completed.")
    return df


def parse_dates(df):
    print("\n[3/5] Parsing date columns...")

    for column, date_format in DATE_FORMATS.items():
        if column not in df.columns:
            continue

        new_column = f"{column}_parsed"

        df[new_column] = pd.to_datetime(
            df[column],
            format=date_format,
            errors="coerce"
        )

        valid_count = int(df[new_column].notna().sum())

        print(
            f"{column}: {valid_count:,} valid dates "
            f"-> {new_column}"
        )

    return df


def convert_numeric_columns(df):
    print("\n[4/5] Creating numeric analysis columns...")

    for column in NUMERIC_COLUMNS:
        if column not in df.columns:
            continue

        new_column = f"{column}_num"

        df[new_column] = pd.to_numeric(
            df[column],
            errors="coerce"
        )

        print(
            f"{new_column}: "
            f"{df[new_column].notna().sum():,} numeric values"
        )

    return df


def save_outputs(df):
    print("\n[5/5] Saving processed dataset and report...")

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    output_file = OUTPUT_DIR / "eurepoc_incidents_cleaned.csv"

    df.to_csv(
        output_file,
        index=False,
        encoding="utf-8-sig"
    )

    duplicate_ids = int(
        df["incident_id"].duplicated().sum()
    )

    report = {
        "project": "CYBERPULSE 360",
        "source_file": RAW_FILE.name,
        "output_file": output_file.name,
        "rows": int(len(df)),
        "columns": int(len(df.columns)),
        "duplicate_incident_ids": duplicate_ids,
        "missing_start_dates_after_parsing": int(
            df["start_date_parsed"].isna().sum()
        ),
        "missing_end_dates_after_parsing": int(
            df["end_date_parsed"].isna().sum()
        ),
        "cleaning_notes": [
            "Original raw columns preserved",
            "Whitespace trimmed from text columns",
            "Blank strings converted to missing values",
            "Date columns parsed into additional columns",
            "Numeric analysis columns created separately",
            "Unknown and Not attributed labels preserved"
        ]
    }

    report_file = (
        REPORT_DIR / "cleaning_quality_report.json"
    )

    with open(report_file, "w", encoding="utf-8") as file:
        json.dump(report, file, indent=4, ensure_ascii=False)

    print(f"\nProcessed dataset: {output_file}")
    print(f"Quality report: {report_file}")
    print(f"Duplicate incident IDs: {duplicate_ids}")


def main():
    print("=" * 65)
    print("CYBERPULSE 360 - DATA CLEANING PIPELINE")
    print("=" * 65)

    df = load_data()
    df = clean_text(df)
    df = parse_dates(df)
    df = convert_numeric_columns(df)

    save_outputs(df)

    print("\n" + "=" * 65)
    print("CLEANING PIPELINE COMPLETED!")
    print("=" * 65)


if __name__ == "__main__":
    main()
