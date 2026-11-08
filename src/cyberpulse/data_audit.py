
from pathlib import Path
import json
import pandas as pd

# CYBERPULSE 360 - DATA AUDIT

PROJECT_DIR = Path(__file__).resolve().parents[2]

DATA_FILE = (
    PROJECT_DIR
    / "data"
    / "raw"
    / "eurepoc"
    / "eurepoc_global_dataset_1_3.csv"
)

REPORT_DIR = PROJECT_DIR / "reports" / "findings"


def print_header(title):
    print("\n" + "=" * 65)
    print(title)
    print("=" * 65)


def load_dataset():
    print_header("DATA LOADING")

    if not DATA_FILE.exists():
        raise FileNotFoundError(
            f"Dataset not found: {DATA_FILE}"
        )

    df = pd.read_csv(
        DATA_FILE,
        encoding="utf-8-sig",
        low_memory=False
    )

    print("Dataset loaded successfully!")
    return df


def basic_information(df):
    print_header("BASIC DATASET INFORMATION")

    print(f"Total Rows    : {df.shape[0]:,}")
    print(f"Total Columns : {df.shape[1]:,}")

    memory = df.memory_usage(deep=True).sum() / 1024**2
    print(f"Memory Usage  : {memory:.2f} MB")

    print("\nFIRST 5 RECORDS:")
    print(df.head().to_string())


def column_information(df):
    print_header("COLUMN INFORMATION")

    for number, column in enumerate(df.columns, start=1):
        print(f"{number:02d}. {column} | {df[column].dtype}")


def missing_value_analysis(df):
    print_header("MISSING VALUE ANALYSIS")

    missing = pd.DataFrame({
        "column": df.columns,
        "missing_count": df.isna().sum().values,
        "missing_percentage": (
            df.isna().mean().values * 100
        ).round(2)
    })

    missing = missing.sort_values(
        by="missing_percentage",
        ascending=False
    )

    print(missing.to_string(index=False))
    return missing


def duplicate_analysis(df):
    print_header("DUPLICATE ANALYSIS")

    duplicate_count = int(df.duplicated().sum())

    print(f"Duplicate Rows: {duplicate_count:,}")
    return duplicate_count


def unique_value_analysis(df):
    print_header("UNIQUE VALUE ANALYSIS")

    unique_counts = df.nunique(dropna=True)

    print(unique_counts.to_string())
    return unique_counts


def date_column_analysis(df):
    print_header("POSSIBLE DATE COLUMNS")

    candidates = [
        col for col in df.columns
        if any(
            word in str(col).lower()
            for word in ["date", "time", "year"]
        )
    ]

    if not candidates:
        print("No obvious date columns found.")
        return []

    for column in candidates:
        print(f"\nColumn: {column}")
        print(df[column].head(5).to_string(index=False))

    return candidates


def save_reports(df, missing, duplicate_count,
                 unique_counts, date_columns):

    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    missing.to_csv(
        REPORT_DIR / "missing_values_report.csv",
        index=False
    )

    unique_counts.rename("unique_count").to_csv(
        REPORT_DIR / "unique_values_report.csv"
    )

    report = {
        "project": "CYBERPULSE 360",
        "dataset": DATA_FILE.name,
        "total_rows": int(df.shape[0]),
        "total_columns": int(df.shape[1]),
        "duplicate_rows": duplicate_count,
        "memory_usage_mb": round(
            df.memory_usage(deep=True).sum() / 1024**2,
            2
        ),
        "date_column_candidates": date_columns,
        "column_names": df.columns.tolist()
    }

    with open(
        REPORT_DIR / "dataset_audit_summary.json",
        "w",
        encoding="utf-8"
    ) as file:
        json.dump(
            report,
            file,
            indent=4,
            ensure_ascii=False
        )

    print_header("REPORTS SAVED")
    print(f"Location: {REPORT_DIR}")


def main():
    print_header("CYBERPULSE 360")
    print("GLOBAL CYBER INCIDENT DATA AUDIT")

    df = load_dataset()

    basic_information(df)
    column_information(df)

    missing = missing_value_analysis(df)
    duplicates = duplicate_analysis(df)
    unique_counts = unique_value_analysis(df)
    date_columns = date_column_analysis(df)

    save_reports(
        df,
        missing,
        duplicates,
        unique_counts,
        date_columns
    )

    print_header("AUDIT COMPLETED SUCCESSFULLY")


if __name__ == "__main__":
    main()
