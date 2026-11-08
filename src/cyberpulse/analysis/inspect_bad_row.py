
import csv
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parents[3]
RAW_FILE = (
    PROJECT_DIR / "data" / "raw" / "eurepoc"
    / "eurepoc_global_dataset_1_3.csv"
)

with open(RAW_FILE, "r", encoding="utf-8-sig", newline="") as file:
    reader = csv.reader(file)
    headers = next(reader)

    for record_number, row in enumerate(reader, start=2):
        if len(row) == len(headers) and row[8].strip() == "12599":
            print("Record:", record_number)
            print("-" * 60)

            for i in list(range(0, 20)) + list(range(75, 85)):
                print(f"{i:02d} | {headers[i]} = {row[i][:100]}")

            break
