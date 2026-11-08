
import csv
import gzip
import json
from pathlib import Path
from collections import Counter
from datetime import datetime, timezone

import pandas as pd
import ijson


# --------------------------------------------------
# PROJECT PATHS
# --------------------------------------------------

PROJECT_DIR = Path(__file__).resolve().parents[3]

RAW_DIR = PROJECT_DIR / "data" / "raw"
REPORT_DIR = PROJECT_DIR / "reports" / "findings"

REPORT_DIR.mkdir(parents=True, exist_ok=True)


def file_size_mb(path):
    return round(path.stat().st_size / (1024 * 1024), 2)


# --------------------------------------------------
# 1. EUREPOC AUDIT
# --------------------------------------------------

def audit_eurepoc():

    path = (
        RAW_DIR / "eurepoc"
        / "eurepoc_global_dataset_1_3.csv"
    )

    df = pd.read_csv(
        path,
        dtype={"incident_id": "string"},
        low_memory=False
    )

    missing = (
        df.isna().sum()
        .reset_index()
    )

    missing.columns = ["column", "missing_count"]

    missing.to_csv(
        REPORT_DIR / "eurepoc_missing_values.csv",
        index=False
    )

    suspicious = 0

    if "incident_type" in df.columns:
        suspicious = int(
            df["incident_type"]
            .astype("string")
            .str.strip()
            .eq("12599")
            .fillna(False)
            .sum()
        )

    return {
        "status": "OK",
        "records": len(df),
        "columns": len(df.columns),
        "unique_incident_ids": int(
            df["incident_id"].nunique()
        ),
        "duplicate_rows": int(
            df.duplicated().sum()
        ),
        "suspicious_records": suspicious,
        "file_size_mb": file_size_mb(path)
    }


# --------------------------------------------------
# 2. NVD AUDIT - STREAMING GZIP JSON
# --------------------------------------------------

def audit_nvd():

    yearly_results = []
    all_ids = set()
    all_files_exist = True

    for year in range(2020, 2027):

        path = (
            RAW_DIR / "nvd"
            / f"nvdcve-2.0-{year}.json.gz"
        )

        if not path.exists():
            all_files_exist = False
            print(f"Missing NVD file: {path.name}")
            continue

        record_count = 0
        missing_ids = 0
        duplicate_ids = 0
        cvss_count = 0
        year_ids = set()

        with gzip.open(path, "rb") as file:

            for item in ijson.items(
                file, "vulnerabilities.item"
            ):

                record_count += 1

                cve = item.get("cve", {})
                cve_id = cve.get("id")

                if not cve_id:
                    missing_ids += 1
                elif cve_id in year_ids:
                    duplicate_ids += 1
                else:
                    year_ids.add(cve_id)

                if cve_id:
                    all_ids.add(cve_id)

                metrics = cve.get("metrics", {})

                if metrics:
                    cvss_count += 1

        yearly_results.append({
            "year": year,
            "records": record_count,
            "unique_cve_ids": len(year_ids),
            "duplicate_ids": duplicate_ids,
            "missing_ids": missing_ids,
            "records_with_cvss": cvss_count,
            "file_size_mb": file_size_mb(path)
        })

    total_records = sum(
        item["records"] for item in yearly_results
    )

    pd.DataFrame(yearly_results).to_csv(
        REPORT_DIR / "nvd_yearly_audit.csv",
        index=False
    )

    return {
        "status": (
            "OK" if all_files_exist else "PARTIAL"
        ),
        "records": total_records,
        "unique_cve_ids": len(all_ids),
        "files_found": len(yearly_results),
        "file_size_mb": round(
            sum(item["file_size_mb"] for item in yearly_results),
            2
        ),
        "yearly_results": yearly_results
    }


# --------------------------------------------------
# 3. CISA KEV AUDIT
# --------------------------------------------------

def audit_cisa():

    path = (
        RAW_DIR / "cisa_kev"
        / "known_exploited_vulnerabilities.json"
    )

    with open(path, "r", encoding="utf-8") as file:
        data = json.load(file)

    vulnerabilities = data.get("vulnerabilities", [])

    cve_ids = [
        item.get("cveID")
        for item in vulnerabilities
        if item.get("cveID")
    ]

    unique_ids = set(cve_ids)

    ransomware_known = sum(
        item.get("knownRansomwareCampaignUse") == "Known"
        for item in vulnerabilities
    )

    return {
        "status": "OK",
        "records": len(vulnerabilities),
        "unique_cve_ids": len(unique_ids),
        "duplicate_cve_ids": len(cve_ids) - len(unique_ids),
        "catalog_count": data.get("count"),
        "catalog_version": data.get("catalogVersion"),
        "ransomware_known_count": ransomware_known,
        "file_size_mb": file_size_mb(path)
    }


# --------------------------------------------------
# 4. MITRE ATT&CK AUDIT
# --------------------------------------------------

def audit_mitre():

    path = (
        RAW_DIR / "mitre_attack"
        / "enterprise-attack.json"
    )

    object_types = Counter()
    object_ids = set()

    total_objects = 0
    duplicate_ids = 0
    missing_ids = 0

    with open(path, "rb") as file:

        for obj in ijson.items(file, "objects.item"):

            total_objects += 1

            object_type = obj.get("type", "unknown")
            object_types[object_type] += 1

            object_id = obj.get("id")

            if not object_id:
                missing_ids += 1
            elif object_id in object_ids:
                duplicate_ids += 1
            else:
                object_ids.add(object_id)

    pd.DataFrame(
        object_types.most_common(),
        columns=["object_type", "object_count"]
    ).to_csv(
        REPORT_DIR / "mitre_object_types.csv",
        index=False
    )

    return {
        "status": "OK",
        "records": total_objects,
        "unique_object_ids": len(object_ids),
        "duplicate_ids": duplicate_ids,
        "missing_ids": missing_ids,
        "attack_patterns": object_types.get(
            "attack-pattern", 0
        ),
        "tactics": object_types.get(
            "x-mitre-tactic", 0
        ),
        "object_types": dict(object_types),
        "file_size_mb": file_size_mb(path)
    }


# --------------------------------------------------
# 5. RANSOMWARE DATA AUDIT
# --------------------------------------------------

def audit_ransomware():

    path = (
        RAW_DIR / "ransomware"
        / "ransomware_leak_site_victims.jsonl"
    )

    records = 0
    invalid_lines = 0
    duplicate_pairs = 0

    field_counts = Counter()
    groups = set()
    countries = set()
    seen_pairs = set()

    important_fields = [
        "group_name",
        "victim_name",
        "country",
        "sector",
        "discovered",
        "published"
    ]

    missing_fields = Counter()

    with open(
        path, "r", encoding="utf-8"
    ) as file:

        for line in file:

            if not line.strip():
                continue

            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                invalid_lines += 1
                continue

            if not isinstance(item, dict):
                invalid_lines += 1
                continue

            records += 1
            field_counts.update(item.keys())

            for field in important_fields:
                if item.get(field) in (None, ""):
                    missing_fields[field] += 1

            group = item.get("group_name")
            victim = item.get("victim_name")
            country = item.get("country")

            if group:
                groups.add(str(group))

            if country:
                countries.add(str(country))

            if group and victim:
                pair = (str(group), str(victim))

                if pair in seen_pairs:
                    duplicate_pairs += 1
                else:
                    seen_pairs.add(pair)

    return {
        "status": "OK",
        "records": records,
        "invalid_lines": invalid_lines,
        "duplicate_group_victim_pairs": duplicate_pairs,
        "unique_groups": len(groups),
        "unique_countries": len(countries),
        "fields": dict(field_counts),
        "missing_important_fields": dict(missing_fields),
        "file_size_mb": file_size_mb(path)
    }


# --------------------------------------------------
# MAIN COMBINED AUDIT
# --------------------------------------------------

def main():

    print("=" * 65)
    print("CYBERPULSE 360 - COMBINED DATASET AUDIT")
    print("=" * 65)

    audit_functions = [
        ("EuRepoC", audit_eurepoc),
        ("NVD", audit_nvd),
        ("CISA KEV", audit_cisa),
        ("MITRE ATT&CK", audit_mitre),
        ("ThreatCluster Ransomware", audit_ransomware)
    ]

    results = {}

    for index, (name, function) in enumerate(
        audit_functions, start=1
    ):

        print(f"\n[{index}/5] Auditing {name}...")

        try:
            results[name] = function()
            print("Status:", results[name]["status"])
            print("Records:", results[name]["records"])

        except Exception as error:
            results[name] = {
                "status": "ERROR",
                "error": str(error)
            }

            print("ERROR:", error)

    # Combined inventory
    inventory = []

    for name, result in results.items():

        inventory.append({
            "dataset": name,
            "status": result["status"],
            "records": result.get("records", 0),
            "file_size_mb": result.get("file_size_mb", 0)
        })

    inventory_path = (
        REPORT_DIR / "combined_dataset_inventory.csv"
    )

    pd.DataFrame(inventory).to_csv(
        inventory_path,
        index=False
    )

    # Full audit report
    report = {
        "project": "CYBERPULSE 360",
        "generated_at_utc": datetime.now(
            timezone.utc
        ).isoformat(),
        "datasets": results
    }

    report_path = (
        REPORT_DIR / "combined_dataset_audit.json"
    )

    with open(
        report_path, "w", encoding="utf-8"
    ) as file:

        json.dump(
            report,
            file,
            indent=4,
            ensure_ascii=False
        )

    print("\n" + "=" * 65)
    print("COMBINED AUDIT SUMMARY")
    print("=" * 65)

    print(pd.DataFrame(inventory).to_string(index=False))

    print("\nReports saved:")
    print("1. combined_dataset_audit.json")
    print("2. combined_dataset_inventory.csv")
    print("3. nvd_yearly_audit.csv")
    print("4. mitre_object_types.csv")
    print("5. eurepoc_missing_values.csv")

    print("\nCOMBINED DATASET AUDIT COMPLETED!")


if __name__ == "__main__":
    main()
