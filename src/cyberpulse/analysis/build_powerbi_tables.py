"""CYBERPULSE 360 - Build Power BI-ready tables from five raw sources.

This script preserves all raw source files and writes curated CSV tables to:
    data/processed/powerbi/

Requires: pandas, ijson (both are already used in the project).
"""

from __future__ import annotations

import csv
import gzip
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import ijson
import pandas as pd


PROJECT_DIR = Path(__file__).resolve().parents[3]
RAW_DIR = PROJECT_DIR / "data" / "raw"
PROCESSED_DIR = PROJECT_DIR / "data" / "processed"
OUTPUT_DIR = PROCESSED_DIR / "powerbi"
REPORT_DIR = PROJECT_DIR / "reports" / "findings"

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
REPORT_DIR.mkdir(parents=True, exist_ok=True)

CSV_ENCODING = "utf-8-sig"


def write_csv(path: Path, fieldnames: list[str]):
    """Open a CSV for streaming writes and return (file, writer)."""
    handle = path.open("w", newline="", encoding=CSV_ENCODING)
    writer = csv.DictWriter(
        handle,
        fieldnames=fieldnames,
        extrasaction="ignore",
        restval="",
    )
    writer.writeheader()
    return handle, writer


def safe_text(value: Any) -> str:
    """Convert nested source values into Power BI-friendly text."""
    if value is None:
        return ""
    if isinstance(value, (list, tuple)):
        return "; ".join(safe_text(item) for item in value)
    if isinstance(value, dict):
        return json.dumps(value, ensure_ascii=False)
    return str(value)


def english_description(items: list[dict]) -> str:
    for item in items or []:
        if item.get("lang") == "en" and item.get("value"):
            return str(item["value"])
    for item in items or []:
        if item.get("value"):
            return str(item["value"])
    return ""


# ---------------------------------------------------------------------------
# 1. EuRepoC: incident fact table + normalized category/country bridges
# ---------------------------------------------------------------------------

def build_eurepoc(summary: dict) -> None:
    source = PROCESSED_DIR / "eurepoc_incidents_analysis_ready.csv"
    if not source.exists():
        raise FileNotFoundError(
            f"Missing {source}. Run the existing quarantine script first."
        )

    df = pd.read_csv(
        source,
        dtype={"incident_id": "string"},
        low_memory=False,
    )
    if "incident_id" not in df.columns:
        raise ValueError("EuRepoC file has no incident_id column.")

    fact_path = OUTPUT_DIR / "fact_incidents.csv"
    df.to_csv(fact_path, index=False, encoding=CSV_ENCODING)

    country_path = OUTPUT_DIR / "bridge_incident_country.csv"
    country_fields = ["incident_id", "country_role", "country_or_status", "value_kind"]
    country_handle, country_writer = write_csv(country_path, country_fields)
    country_links = 0
    status_values = {"unknown", "not attributed", "not available"}

    try:
        for source_column, role in [
            ("initiator_country", "initiator"),
            ("receiver_country", "receiver"),
        ]:
            if source_column not in df.columns:
                continue
            seen = set()
            for incident_id, raw_value in zip(df["incident_id"], df[source_column]):
                if pd.isna(raw_value):
                    continue
                for value in str(raw_value).split(";"):
                    label = value.strip()
                    if not label:
                        continue
                    key = (str(incident_id), role, label.casefold())
                    if key in seen:
                        continue
                    seen.add(key)
                    kind = "attribution_status" if label.casefold() in status_values else "source_country_label"
                    country_writer.writerow({
                        "incident_id": str(incident_id),
                        "country_role": role,
                        "country_or_status": label,
                        "value_kind": kind,
                    })
                    country_links += 1
    finally:
        country_handle.close()

    type_path = OUTPUT_DIR / "bridge_incident_type.csv"
    type_fields = ["incident_id", "incident_type"]
    type_handle, type_writer = write_csv(type_path, type_fields)
    type_links = 0
    try:
        if "incident_type" in df.columns:
            for incident_id, raw_value in zip(df["incident_id"], df["incident_type"]):
                if pd.isna(raw_value):
                    continue
                values = {part.strip() for part in str(raw_value).split(";") if part.strip()}
                for value in sorted(values):
                    type_writer.writerow({"incident_id": str(incident_id), "incident_type": value})
                    type_links += 1
    finally:
        type_handle.close()

    summary["datasets"]["EuRepoC"] = {
        "status": "OK",
        "incident_rows": int(len(df)),
        "incident_columns": int(len(df.columns)),
        "unique_incident_ids": int(df["incident_id"].nunique()),
        "incident_country_links": country_links,
        "incident_type_links": type_links,
        "outputs": [
            "fact_incidents.csv",
            "bridge_incident_country.csv",
            "bridge_incident_type.csv",
        ],
    }


# ---------------------------------------------------------------------------
# 2. NVD: CVE dimension + CVE-to-CWE bridge (stream from gzip JSON)
# ---------------------------------------------------------------------------

def build_nvd(summary: dict) -> set[str]:
    cve_path = OUTPUT_DIR / "dim_cve.csv"
    weakness_path = OUTPUT_DIR / "bridge_cve_weakness.csv"

    cve_fields = [
        "cve_id", "cve_id_year", "source_identifier", "published",
        "last_modified", "vulnerability_status", "description_en",
        "cvss_version", "cvss_base_score", "cvss_severity", "cvss_vector",
        "attack_vector", "attack_complexity", "privileges_required",
        "user_interaction", "scope", "confidentiality_impact",
        "integrity_impact", "availability_impact", "exploitability_score",
        "impact_score", "has_cvss",
    ]
    weakness_fields = ["cve_id", "cwe_id", "cwe_description"]

    cve_handle, cve_writer = write_csv(cve_path, cve_fields)
    weakness_handle, weakness_writer = write_csv(weakness_path, weakness_fields)

    all_cve_ids: set[str] = set()
    total_records = 0
    duplicate_ids = 0
    missing_ids = 0
    weakness_links = 0
    cvss_records = 0
    year_results = []
    metric_keys = [
        ("cvssMetricV40", "4.0"),
        ("cvssMetricV31", "3.1"),
        ("cvssMetricV30", "3.0"),
        ("cvssMetricV2", "2.0"),
    ]

    try:
        for year in range(2020, datetime.now().year + 1):
            path = RAW_DIR / "nvd" / f"nvdcve-2.0-{year}.json.gz"
            if not path.exists():
                raise FileNotFoundError(f"Missing NVD feed: {path}")

            year_count = 0
            year_cvss = 0
            with gzip.open(path, "rb") as handle:
                for item in ijson.items(handle, "vulnerabilities.item"):
                    cve = item.get("cve") or {}
                    cve_id = cve.get("id")
                    if not cve_id:
                        missing_ids += 1
                        continue
                    if cve_id in all_cve_ids:
                        duplicate_ids += 1
                        continue
                    all_cve_ids.add(cve_id)
                    total_records += 1
                    year_count += 1

                    chosen_metric = None
                    chosen_version = ""
                    metrics = cve.get("metrics") or {}
                    for metric_key, version in metric_keys:
                        entries = metrics.get(metric_key) or []
                        if entries:
                            chosen_metric = next(
                                (entry for entry in entries if entry.get("type") == "Primary"),
                                entries[0],
                            )
                            chosen_version = version
                            break

                    cvss_data = (chosen_metric or {}).get("cvssData") or {}
                    if chosen_metric:
                        cvss_records += 1
                        year_cvss += 1

                    id_match = re.match(r"CVE-(\d{4})-", cve_id)
                    cve_writer.writerow({
                        "cve_id": cve_id,
                        "cve_id_year": id_match.group(1) if id_match else "",
                        "source_identifier": cve.get("sourceIdentifier", ""),
                        "published": cve.get("published", ""),
                        "last_modified": cve.get("lastModified", ""),
                        "vulnerability_status": cve.get("vulnStatus", ""),
                        "description_en": english_description(cve.get("descriptions") or []),
                        "cvss_version": chosen_version,
                        "cvss_base_score": cvss_data.get("baseScore", ""),
                        "cvss_severity": cvss_data.get("baseSeverity") or (chosen_metric or {}).get("baseSeverity", ""),
                        "cvss_vector": cvss_data.get("vectorString", ""),
                        "attack_vector": cvss_data.get("attackVector", ""),
                        "attack_complexity": cvss_data.get("attackComplexity", ""),
                        "privileges_required": cvss_data.get("privilegesRequired", ""),
                        "user_interaction": cvss_data.get("userInteraction", ""),
                        "scope": cvss_data.get("scope", ""),
                        "confidentiality_impact": cvss_data.get("confidentialityImpact", ""),
                        "integrity_impact": cvss_data.get("integrityImpact", ""),
                        "availability_impact": cvss_data.get("availabilityImpact", ""),
                        "exploitability_score": (chosen_metric or {}).get("exploitabilityScore", ""),
                        "impact_score": (chosen_metric or {}).get("impactScore", ""),
                        "has_cvss": bool(chosen_metric),
                    })

                    seen_cwes = set()
                    for weakness in cve.get("weaknesses") or []:
                        for desc in weakness.get("description") or []:
                            if desc.get("lang") != "en":
                                continue
                            text = str(desc.get("value", ""))
                            for cwe_id in re.findall(r"CWE-\d+", text, flags=re.IGNORECASE):
                                cwe_id = cwe_id.upper()
                                if cwe_id in seen_cwes:
                                    continue
                                seen_cwes.add(cwe_id)
                                weakness_writer.writerow({
                                    "cve_id": cve_id,
                                    "cwe_id": cwe_id,
                                    "cwe_description": text,
                                })
                                weakness_links += 1

                    if total_records % 25000 == 0:
                        print(f"  NVD processed: {total_records:,} CVEs")

            year_results.append({
                "feed_year": year,
                "records_written": year_count,
                "records_with_cvss": year_cvss,
            })
            print(f"  NVD {year}: {year_count:,} CVEs written")
    finally:
        cve_handle.close()
        weakness_handle.close()

    summary["datasets"]["NVD"] = {
        "status": "OK",
        "cve_records_written": total_records,
        "unique_cve_ids": len(all_cve_ids),
        "duplicate_ids_skipped": duplicate_ids,
        "missing_ids_skipped": missing_ids,
        "records_with_cvss": cvss_records,
        "cve_weakness_links": weakness_links,
        "yearly_results": year_results,
        "outputs": ["dim_cve.csv", "bridge_cve_weakness.csv"],
    }
    return all_cve_ids


# ---------------------------------------------------------------------------
# 3. CISA KEV: KEV fact table; CVE ID will link to dim_cve
# ---------------------------------------------------------------------------

def build_cisa_kev(nvd_ids: set[str], summary: dict) -> None:
    source = RAW_DIR / "cisa_kev" / "known_exploited_vulnerabilities.json"
    with source.open("r", encoding="utf-8") as handle:
        data = json.load(handle)

    vulnerabilities = data.get("vulnerabilities") or []
    fields = [
        "cve_id", "vendor_project", "product", "vulnerability_name",
        "date_added", "short_description", "required_action", "due_date",
        "known_ransomware_campaign_use", "notes", "cwes",
        "matched_to_nvd",
    ]
    path = OUTPUT_DIR / "fact_cisa_kev.csv"
    out, writer = write_csv(path, fields)
    kev_ids = set()
    try:
        for item in vulnerabilities:
            cve_id = item.get("cveID", "")
            if cve_id:
                kev_ids.add(cve_id)
            writer.writerow({
                "cve_id": cve_id,
                "vendor_project": item.get("vendorProject", ""),
                "product": item.get("product", ""),
                "vulnerability_name": item.get("vulnerabilityName", ""),
                "date_added": item.get("dateAdded", ""),
                "short_description": item.get("shortDescription", ""),
                "required_action": item.get("requiredAction", ""),
                "due_date": item.get("dueDate", ""),
                "known_ransomware_campaign_use": item.get("knownRansomwareCampaignUse", ""),
                "notes": item.get("notes", ""),
                "cwes": safe_text(item.get("cwes", [])),
                "matched_to_nvd": cve_id in nvd_ids,
            })
    finally:
        out.close()

    summary["datasets"]["CISA_KEV"] = {
        "status": "OK",
        "catalog_count": len(vulnerabilities),
        "unique_cve_ids": len(kev_ids),
        "matched_to_nvd": len(kev_ids & nvd_ids),
        "not_found_in_nvd_snapshot": len(kev_ids - nvd_ids),
        "catalog_version": data.get("catalogVersion", ""),
        "catalog_date_released": data.get("dateReleased", ""),
        "outputs": ["fact_cisa_kev.csv"],
    }


# ---------------------------------------------------------------------------
# 4. MITRE ATT&CK: objects dimension + relationship bridge
# ---------------------------------------------------------------------------

def build_mitre(summary: dict) -> None:
    source = RAW_DIR / "mitre_attack" / "enterprise-attack.json"
    object_path = OUTPUT_DIR / "dim_mitre_attack_object.csv"
    relationship_path = OUTPUT_DIR / "bridge_mitre_relationship.csv"

    object_fields = [
        "object_id", "object_type", "name", "description", "mitre_external_id",
        "created", "modified", "revoked", "deprecated", "platforms",
        "kill_chain_phases", "aliases",
    ]
    relationship_fields = [
        "relationship_id", "source_ref", "target_ref", "relationship_type",
        "description", "created", "modified", "revoked",
    ]

    obj_handle, obj_writer = write_csv(object_path, object_fields)
    rel_handle, rel_writer = write_csv(relationship_path, relationship_fields)
    total = 0
    object_count = 0
    relationship_count = 0
    type_counts = Counter()
    seen_ids = set()
    duplicate_ids = 0
    missing_ids = 0

    try:
        with source.open("rb") as handle:
            for obj in ijson.items(handle, "objects.item"):
                total += 1
                obj_type = obj.get("type", "unknown")
                type_counts[obj_type] += 1
                object_id = obj.get("id", "")

                if not object_id:
                    missing_ids += 1
                elif object_id in seen_ids:
                    duplicate_ids += 1
                    continue
                else:
                    seen_ids.add(object_id)

                if obj_type == "relationship":
                    rel_writer.writerow({
                        "relationship_id": object_id,
                        "source_ref": obj.get("source_ref", ""),
                        "target_ref": obj.get("target_ref", ""),
                        "relationship_type": obj.get("relationship_type", ""),
                        "description": obj.get("description", ""),
                        "created": obj.get("created", ""),
                        "modified": obj.get("modified", ""),
                        "revoked": obj.get("revoked", False),
                    })
                    relationship_count += 1
                    continue

                mitre_external_id = ""
                for ref in obj.get("external_references") or []:
                    if ref.get("external_id") and ref.get("source_name") in {
                        "mitre-attack", "mitre-mobile-attack", "mitre-ics-attack"
                    }:
                        mitre_external_id = ref["external_id"]
                        break

                phases = []
                for phase in obj.get("kill_chain_phases") or []:
                    phase_name = phase.get("phase_name", "")
                    chain_name = phase.get("kill_chain_name", "")
                    if phase_name:
                        phases.append(f"{chain_name}:{phase_name}" if chain_name else phase_name)

                obj_writer.writerow({
                    "object_id": object_id,
                    "object_type": obj_type,
                    "name": obj.get("name", ""),
                    "description": obj.get("description", ""),
                    "mitre_external_id": mitre_external_id,
                    "created": obj.get("created", ""),
                    "modified": obj.get("modified", ""),
                    "revoked": obj.get("revoked", False),
                    "deprecated": obj.get("x_mitre_deprecated", False),
                    "platforms": safe_text(obj.get("x_mitre_platforms", [])),
                    "kill_chain_phases": safe_text(phases),
                    "aliases": safe_text(obj.get("aliases", [])),
                })
                object_count += 1
    finally:
        obj_handle.close()
        rel_handle.close()

    pd.DataFrame(
        type_counts.most_common(),
        columns=["object_type", "source_record_count"],
    ).to_csv(OUTPUT_DIR / "mitre_object_type_counts.csv", index=False, encoding=CSV_ENCODING)

    summary["datasets"]["MITRE_ATT&CK"] = {
        "status": "OK",
        "source_objects": total,
        "dimension_objects_written": object_count,
        "relationships_written": relationship_count,
        "duplicate_object_ids_skipped": duplicate_ids,
        "missing_object_ids": missing_ids,
        "object_type_counts": dict(type_counts),
        "outputs": [
            "dim_mitre_attack_object.csv",
            "bridge_mitre_relationship.csv",
            "mitre_object_type_counts.csv",
        ],
    }


# ---------------------------------------------------------------------------
# 5. Ransomware victim listings: preserve source claims, don't infer incidents
# ---------------------------------------------------------------------------

def build_ransomware(summary: dict) -> None:
    source = RAW_DIR / "ransomware" / "ransomware_leak_site_victims.jsonl"
    fields = [
        "group_name", "victim_name", "country", "sector", "discovered",
        "published", "delisted", "delisted_at", "has_website",
        "group_victim_seq", "group_total_victims", "is_headline_style",
    ]
    path = OUTPUT_DIR / "fact_ransomware_victim.csv"
    out, writer = write_csv(path, fields)

    count = 0
    invalid_lines = 0
    groups = set()
    countries = set()
    duplicate_pairs = 0
    seen_pairs = set()

    try:
        with source.open("r", encoding="utf-8") as handle:
            for line in handle:
                if not line.strip():
                    continue
                try:
                    item = json.loads(line)
                    if not isinstance(item, dict):
                        raise ValueError("JSON line is not an object")
                except (json.JSONDecodeError, ValueError):
                    invalid_lines += 1
                    continue

                count += 1
                group = safe_text(item.get("group_name"))
                victim = safe_text(item.get("victim_name"))
                country = safe_text(item.get("country"))
                if group:
                    groups.add(group)
                if country:
                    countries.add(country)
                if group and victim:
                    pair = (group, victim)
                    if pair in seen_pairs:
                        duplicate_pairs += 1
                    else:
                        seen_pairs.add(pair)

                writer.writerow({field: safe_text(item.get(field)) for field in fields})
    finally:
        out.close()

    summary["datasets"]["Ransomware"] = {
        "status": "OK",
        "source_rows_written": count,
        "invalid_json_lines_skipped": invalid_lines,
        "unique_groups": len(groups),
        "unique_country_labels": len(countries),
        "duplicate_group_victim_pairs_observed": duplicate_pairs,
        "interpretation": "Victim listings are source/group claims, not independently verified incidents.",
        "outputs": ["fact_ransomware_victim.csv"],
    }


# ---------------------------------------------------------------------------
# Power BI relationship guide
# ---------------------------------------------------------------------------

def write_relationship_guide() -> None:
    rows = [
        {
            "from_table": "dim_cve", "from_column": "cve_id",
            "to_table": "fact_cisa_kev", "to_column": "cve_id",
            "cardinality": "1 to 1 (KEV is a subset of NVD; verify key uniqueness)",
            "note": "Use CVE ID. Check unmatched KEV IDs in pipeline_summary.json.",
        },
        {
            "from_table": "fact_incidents", "from_column": "incident_id",
            "to_table": "bridge_incident_country", "to_column": "incident_id",
            "cardinality": "1 to many",
            "note": "Country labels and attribution-status values are retained as provided by EuRepoC.",
        },
        {
            "from_table": "fact_incidents", "from_column": "incident_id",
            "to_table": "bridge_incident_type", "to_column": "incident_id",
            "cardinality": "1 to many",
            "note": "One incident may have multiple incident-type labels.",
        },
        {
            "from_table": "dim_mitre_attack_object", "from_column": "object_id",
            "to_table": "bridge_mitre_relationship", "to_column": "source_ref",
            "cardinality": "1 to many",
            "note": "MITRE relationship source role. Add a second role-playing copy for target_ref if needed.",
        },
        {
            "from_table": "dim_mitre_attack_object", "from_column": "object_id",
            "to_table": "bridge_mitre_relationship", "to_column": "target_ref",
            "cardinality": "1 to many",
            "note": "MITRE relationship target role. Keep role paths unambiguous in the model.",
        },
        {
            "from_table": "fact_ransomware_victim", "from_column": "",
            "to_table": "", "to_column": "",
            "cardinality": "No direct relationship supplied",
            "note": "Keep separate until a defensible shared identifier or reviewed mapping exists.",
        },
    ]
    pd.DataFrame(rows).to_csv(
        OUTPUT_DIR / "powerbi_relationship_guide.csv",
        index=False,
        encoding=CSV_ENCODING,
    )


def main() -> None:
    print("=" * 68)
    print("CYBERPULSE 360 - POWER BI TABLE BUILDER")
    print("=" * 68)
    print("Raw source files will not be modified.")
    print(f"Output folder: {OUTPUT_DIR}\n")

    summary: dict[str, Any] = {
        "project": "CYBERPULSE 360",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "output_folder": str(OUTPUT_DIR),
        "datasets": {},
    }

    build_eurepoc(summary)
    print("[1/5] EuRepoC tables built.")

    nvd_ids = build_nvd(summary)
    print("[2/5] NVD CVE and CWE tables built.")

    build_cisa_kev(nvd_ids, summary)
    print("[3/5] CISA KEV table built and CVE IDs matched to NVD.")

    build_mitre(summary)
    print("[4/5] MITRE objects and relationships built.")

    build_ransomware(summary)
    print("[5/5] Ransomware victim table built.")

    write_relationship_guide()

    summary_path = OUTPUT_DIR / "pipeline_summary.json"
    with summary_path.open("w", encoding="utf-8") as handle:
        json.dump(summary, handle, indent=4, ensure_ascii=False)

    print("\n" + "=" * 68)
    print("POWER BI TABLE BUILD COMPLETED")
    print("=" * 68)
    for name, result in summary["datasets"].items():
        print(f"{name}: {result.get('status')} | "
              f"rows={result.get('incident_rows', result.get('cve_records_written', result.get('catalog_count', result.get('dimension_objects_written', result.get('source_rows_written', 0)))))}")

    kev = summary["datasets"]["CISA_KEV"]
    print(f"\nCISA KEV matched to NVD: {kev['matched_to_nvd']}")
    print(f"CISA KEV not found in NVD snapshot: {kev['not_found_in_nvd_snapshot']}")
    print(f"\nTables saved in: {OUTPUT_DIR}")
    print("Summary: pipeline_summary.json")
    print("Relationship guide: powerbi_relationship_guide.csv")


if __name__ == "__main__":
    main()
