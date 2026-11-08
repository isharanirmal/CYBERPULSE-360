
import pandas as pd
from pathlib import Path

# Project paths
PROJECT_DIR = Path(__file__).resolve().parents[3]

INPUT_FILE = (
    PROJECT_DIR / "data" / "processed"
    / "eurepoc_incidents_analysis_ready.csv"
)

INTERIM_DIR = PROJECT_DIR / "data" / "interim"
REPORT_DIR = PROJECT_DIR / "reports" / "findings"

INTERIM_DIR.mkdir(parents=True, exist_ok=True)
REPORT_DIR.mkdir(parents=True, exist_ok=True)

print("=" * 60)
print("CYBERPULSE 360 - COUNTRY ATTRIBUTION ANALYSIS")
print("=" * 60)

# Load dataset
df = pd.read_csv(
    INPUT_FILE,
    dtype={"incident_id": "string"},
    low_memory=False
)

# Check required columns
required = ["incident_id", "initiator_country"]

if not all(col in df.columns for col in required):
    raise ValueError("Required columns are missing from dataset.")

# Prepare country values
country_data = df[required].copy()

country_data["initiator_country"] = (
    country_data["initiator_country"]
    .astype("string")
    .str.strip()
)

missing_count = (
    country_data["initiator_country"].isna()
    | country_data["initiator_country"].eq("")
).sum()

# Split multiple countries into separate rows
country_links = country_data.dropna(
    subset=["initiator_country"]
).copy()

country_links = country_links[
    country_links["initiator_country"] != ""
]

country_links["initiator_country"] = (
    country_links["initiator_country"].str.split(";", regex=False)
)

country_links = country_links.explode("initiator_country")

country_links["initiator_country"] = (
    country_links["initiator_country"].str.strip()
)

country_links = country_links[
    country_links["initiator_country"] != ""
].dropna(subset=["initiator_country"])

# Remove duplicate country entries within the same incident
country_links = country_links.drop_duplicates(
    subset=["incident_id", "initiator_country"]
)

# Separate attribution statuses from actual countries
status_values = [
    "Unknown",
    "Not attributed",
    "Not available"
]

status_links = country_links[
    country_links["initiator_country"].isin(status_values)
]

country_only = country_links[
    ~country_links["initiator_country"].isin(status_values)
]

# Count actual country associations
country_counts = (
    country_only.groupby("initiator_country")["incident_id"]
    .nunique()
    .reset_index(name="incident_count")
    .sort_values("incident_count", ascending=False)
)

# Count attribution statuses separately
status_counts = (
    status_links.groupby("initiator_country")["incident_id"]
    .nunique()
    .reset_index(name="incident_count")
    .sort_values("incident_count", ascending=False)
)

# Count incidents linked to multiple distinct countries
multi_country_count = (
    country_only.groupby("incident_id")["initiator_country"]
    .nunique()
    .gt(1)
    .sum()
)

# Save outputs
country_links.to_csv(
    INTERIM_DIR / "initiator_country_links.csv",
    index=False
)

country_counts.to_csv(
    REPORT_DIR / "initiator_country_counts.csv",
    index=False
)

status_counts.to_csv(
    REPORT_DIR / "initiator_attribution_status.csv",
    index=False
)

# Display results
print("\n[1] DATASET OVERVIEW")
print("-" * 40)
print("Total incidents:", df["incident_id"].nunique())
print("Missing country values:", missing_count)
print("Unique incident-country links:", len(country_links))

print("\n[2] TOP 15 INITIATOR COUNTRIES")
print("-" * 40)
print(country_counts.head(15).to_string(index=False))

print("\n[3] ATTRIBUTION STATUS")
print("-" * 40)
print(status_counts.to_string(index=False))

print("\n[4] MULTI-COUNTRY INCIDENTS")
print("-" * 40)
print("Incidents linked to multiple countries:", multi_country_count)

print("\n[5] OUTPUT FILES")
print("-" * 40)
print("initiator_country_links.csv")
print("initiator_country_counts.csv")
print("initiator_attribution_status.csv")

print("\nCOUNTRY ATTRIBUTION ANALYSIS COMPLETED!")
