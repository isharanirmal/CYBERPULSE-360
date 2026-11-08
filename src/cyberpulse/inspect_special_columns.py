from pathlib import Path
import pandas as pd

PROJECT_DIR = Path(__file__).resolve().parents[2]

RAW_FILE = (
    PROJECT_DIR / "data" / "raw" / "eurepoc"
    / "eurepoc_global_dataset_1_3.csv"
)

df = pd.read_csv(
    RAW_FILE,
    encoding="utf-8-sig",
    low_memory=False,
    dtype={"incident_id": "string"}
)

columns = ["target_multiplier", "casualties"]

for column in columns:
    print("\n" + "=" * 60)
    print(f"COLUMN: {column}")
    print("=" * 60)

    if column not in df.columns:
        print("Column not found!")
        continue

    print("\nData type:", df[column].dtype)
    print("\nNon-empty value count:", df[column].notna().sum())
    print("\nUnique values (first 30):")

    print(df[column].dropna().astype(str).value_counts().head(30))

    print("\nSample values:")
    print(df[column].dropna().head(10).to_string(index=False))