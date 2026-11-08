"""Load CYBERPULSE 360 Power BI-ready CSV tables into PostgreSQL.

Creates/refreshes tables in the dedicated `cyberpulse` schema of the
`cyberpulse360` database. Raw source files and generated CSVs are not changed.

Usage from project root:
    python src/cyberpulse/analysis/load_powerbi_to_postgres.py

The PostgreSQL password is requested interactively and is never saved.
"""
from __future__ import annotations

import csv
import getpass
import re
import sys
from pathlib import Path

try:
    import psycopg2
    from psycopg2 import sql
except ImportError:
    print("Missing dependency: psycopg2-binary")
    print("Install it with: python -m pip install psycopg2-binary")
    sys.exit(1)

PROJECT_DIR = Path(__file__).resolve().parents[3]
INPUT_DIR = PROJECT_DIR / "data" / "processed" / "powerbi"
SCHEMA = "cyberpulse"

# The nine curated tables produced by build_powerbi_tables.py.
# Column types are intentionally explicit where the source structure is stable.
FIXED_TABLES: dict[str, list[tuple[str, str]]] = {
    "bridge_incident_country": [
        ("incident_id", "TEXT"),
        ("country_role", "TEXT"),
        ("country_or_status", "TEXT"),
        ("value_kind", "TEXT"),
    ],
    "bridge_incident_type": [
        ("incident_id", "TEXT"),
        ("incident_type", "TEXT"),
    ],
    "dim_cve": [
        ("cve_id", "TEXT"),
        ("cve_id_year", "SMALLINT"),
        ("source_identifier", "TEXT"),
        ("published", "TIMESTAMPTZ"),
        ("last_modified", "TIMESTAMPTZ"),
        ("vulnerability_status", "TEXT"),
        ("description_en", "TEXT"),
        ("cvss_version", "TEXT"),
        ("cvss_base_score", "DOUBLE PRECISION"),
        ("cvss_severity", "TEXT"),
        ("cvss_vector", "TEXT"),
        ("attack_vector", "TEXT"),
        ("attack_complexity", "TEXT"),
        ("privileges_required", "TEXT"),
        ("user_interaction", "TEXT"),
        ("scope", "TEXT"),
        ("confidentiality_impact", "TEXT"),
        ("integrity_impact", "TEXT"),
        ("availability_impact", "TEXT"),
        ("exploitability_score", "DOUBLE PRECISION"),
        ("impact_score", "DOUBLE PRECISION"),
        ("has_cvss", "BOOLEAN"),
    ],
    "bridge_cve_weakness": [
        ("cve_id", "TEXT"),
        ("cwe_id", "TEXT"),
        ("cwe_description", "TEXT"),
    ],
    "fact_cisa_kev": [
        ("cve_id", "TEXT"),
        ("vendor_project", "TEXT"),
        ("product", "TEXT"),
        ("vulnerability_name", "TEXT"),
        ("date_added", "DATE"),
        ("short_description", "TEXT"),
        ("required_action", "TEXT"),
        ("due_date", "DATE"),
        ("known_ransomware_campaign_use", "TEXT"),
        ("notes", "TEXT"),
        ("cwes", "TEXT"),
        ("matched_to_nvd", "BOOLEAN"),
    ],
    "dim_mitre_attack_object": [
        ("object_id", "TEXT"),
        ("object_type", "TEXT"),
        ("name", "TEXT"),
        ("description", "TEXT"),
        ("mitre_external_id", "TEXT"),
        ("created", "TIMESTAMPTZ"),
        ("modified", "TIMESTAMPTZ"),
        ("revoked", "BOOLEAN"),
        ("deprecated", "BOOLEAN"),
        ("platforms", "TEXT"),
        ("kill_chain_phases", "TEXT"),
        ("aliases", "TEXT"),
    ],
    "bridge_mitre_relationship": [
        ("relationship_id", "TEXT"),
        ("source_ref", "TEXT"),
        ("target_ref", "TEXT"),
        ("relationship_type", "TEXT"),
        ("description", "TEXT"),
        ("created", "TIMESTAMPTZ"),
        ("modified", "TIMESTAMPTZ"),
        ("revoked", "BOOLEAN"),
    ],
    "fact_ransomware_victim": [
        ("group_name", "TEXT"),
        ("victim_name", "TEXT"),
        ("country", "TEXT"),
        ("sector", "TEXT"),
        # Preserve source date strings as text until source date formats are validated.
        ("discovered", "TEXT"),
        ("published", "TEXT"),
        ("delisted", "TEXT"),
        ("delisted_at", "TEXT"),
        ("has_website", "BOOLEAN"),
        ("group_victim_seq", "BIGINT"),
        ("group_total_victims", "BIGINT"),
        ("is_headline_style", "BOOLEAN"),
    ],
}

TABLE_FILES = {
    "fact_incidents": "fact_incidents.csv",
    "bridge_incident_country": "bridge_incident_country.csv",
    "bridge_incident_type": "bridge_incident_type.csv",
    "dim_cve": "dim_cve.csv",
    "bridge_cve_weakness": "bridge_cve_weakness.csv",
    "fact_cisa_kev": "fact_cisa_kev.csv",
    "dim_mitre_attack_object": "dim_mitre_attack_object.csv",
    "bridge_mitre_relationship": "bridge_mitre_relationship.csv",
    "fact_ransomware_victim": "fact_ransomware_victim.csv",
}


def normalize_header(name: str) -> str:
    value = re.sub(r"[^a-zA-Z0-9_]+", "_", name.strip()).strip("_").lower()
    if not value:
        value = "unnamed_column"
    if value[0].isdigit():
        value = "col_" + value
    return value


def read_headers(path: Path) -> list[str]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.reader(handle)
        try:
            original = next(reader)
        except StopIteration:
            raise ValueError(f"CSV is empty: {path.name}")
    normalized = [normalize_header(item) for item in original]
    if len(normalized) != len(set(normalized)):
        duplicates = sorted({name for name in normalized if normalized.count(name) > 1})
        raise ValueError(
            f"Column names collide after SQL-safe normalization in {path.name}: {duplicates}"
        )
    return normalized


def incident_column_type(column: str) -> str:
    if column == "incident_id":
        return "TEXT"
    if column.endswith("_parsed"):
        return "DATE"
    if column.endswith("_num"):
        return "DOUBLE PRECISION"
    return "TEXT"


def get_table_columns(table: str, path: Path) -> list[tuple[str, str]]:
    if table == "fact_incidents":
        return [(column, incident_column_type(column)) for column in read_headers(path)]
    columns = FIXED_TABLES[table]
    actual_headers = read_headers(path)
    expected_headers = [name for name, _ in columns]
    if actual_headers != expected_headers:
        raise ValueError(
            f"Unexpected columns in {path.name}.\n"
            f"Expected: {expected_headers}\nGot:      {actual_headers}"
        )
    return columns


def create_and_copy_table(cur, table: str, path: Path, columns: list[tuple[str, str]]) -> int:
    col_defs = sql.SQL(", ").join(
        sql.SQL("{} {}").format(sql.Identifier(name), sql.SQL(data_type))
        for name, data_type in columns
    )
    cur.execute(
        sql.SQL("DROP TABLE IF EXISTS {}.{} ").format(
            sql.Identifier(SCHEMA), sql.Identifier(table)
        )
    )
    cur.execute(
        sql.SQL("CREATE TABLE {}.{} ({})").format(
            sql.Identifier(SCHEMA), sql.Identifier(table), col_defs
        )
    )

    column_list = sql.SQL(", ").join(
        sql.Identifier(name) for name, _ in columns
    )
    copy_statement = sql.SQL(
        "COPY {}.{} ({}) FROM STDIN WITH (FORMAT CSV, HEADER TRUE, ENCODING 'UTF8', NULL '')"
    ).format(
        sql.Identifier(SCHEMA), sql.Identifier(table), column_list
    )
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        cur.copy_expert(copy_statement.as_string(cur), handle)
    return cur.rowcount


def add_constraints_and_indexes(cur) -> None:
    # Primary keys are based on uniqueness checks already performed in the build pipeline.
    cur.execute(f"ALTER TABLE {SCHEMA}.fact_incidents ADD PRIMARY KEY (incident_id)")
    cur.execute(f"ALTER TABLE {SCHEMA}.dim_cve ADD PRIMARY KEY (cve_id)")
    cur.execute(f"ALTER TABLE {SCHEMA}.dim_mitre_attack_object ADD PRIMARY KEY (object_id)")
    cur.execute(f"ALTER TABLE {SCHEMA}.bridge_mitre_relationship ADD PRIMARY KEY (relationship_id)")
    cur.execute(
        f"ALTER TABLE {SCHEMA}.bridge_cve_weakness "
        "ADD CONSTRAINT pk_bridge_cve_weakness PRIMARY KEY (cve_id, cwe_id)"
    )

    # Defensible foreign keys. CISA KEV is intentionally not constrained to NVD:
    # the source snapshot contains CVE IDs outside the downloaded 2020-2026 NVD range.
    cur.execute(
        f"ALTER TABLE {SCHEMA}.bridge_incident_country "
        f"ADD CONSTRAINT fk_incident_country_incident FOREIGN KEY (incident_id) "
        f"REFERENCES {SCHEMA}.fact_incidents (incident_id)"
    )
    cur.execute(
        f"ALTER TABLE {SCHEMA}.bridge_incident_type "
        f"ADD CONSTRAINT fk_incident_type_incident FOREIGN KEY (incident_id) "
        f"REFERENCES {SCHEMA}.fact_incidents (incident_id)"
    )
    cur.execute(
        f"ALTER TABLE {SCHEMA}.bridge_cve_weakness "
        f"ADD CONSTRAINT fk_cve_weakness_cve FOREIGN KEY (cve_id) "
        f"REFERENCES {SCHEMA}.dim_cve (cve_id)"
    )

    indexes = [
        ("fact_incidents", "start_date_parsed"),
        ("fact_incidents", "weighted_intensity_num"),
        ("dim_cve", "cvss_severity"),
        ("dim_cve", "cve_id_year"),
        ("fact_cisa_kev", "cve_id"),
        ("bridge_cve_weakness", "cwe_id"),
        ("bridge_incident_country", "country_or_status"),
        ("bridge_incident_type", "incident_type"),
        ("bridge_mitre_relationship", "source_ref"),
        ("bridge_mitre_relationship", "target_ref"),
        ("fact_ransomware_victim", "group_name"),
        ("fact_ransomware_victim", "country"),
        ("fact_ransomware_victim", "sector"),
    ]
    for table, column in indexes:
        cur.execute(
            "SELECT 1 FROM information_schema.columns "
            "WHERE table_schema = %s AND table_name = %s AND column_name = %s",
            (SCHEMA, table, column),
        )
        if cur.fetchone():
            index_name = f"ix_{table}_{column}"
            cur.execute(
                sql.SQL("CREATE INDEX {} ON {}.{} ({})").format(
                    sql.Identifier(index_name),
                    sql.Identifier(SCHEMA),
                    sql.Identifier(table),
                    sql.Identifier(column),
                )
            )


def main() -> None:
    print("=" * 68)
    print("CYBERPULSE 360 - LOAD POWER BI TABLES INTO POSTGRESQL")
    print("=" * 68)
    print(f"Database: cyberpulse360 | Schema: {SCHEMA}")
    print(f"CSV folder: {INPUT_DIR}")
    print("This refreshes only the nine CYBERPULSE tables in the dedicated schema.")
    print("Raw datasets and Power BI-ready CSV files are not modified.\n")

    if not INPUT_DIR.exists():
        raise FileNotFoundError(f"Power BI CSV folder not found: {INPUT_DIR}")

    files = {table: INPUT_DIR / filename for table, filename in TABLE_FILES.items()}
    missing = [str(path) for path in files.values() if not path.exists()]
    if missing:
        raise FileNotFoundError("Missing required CSV file(s):\n" + "\n".join(missing))

    password = getpass.getpass("PostgreSQL password for user 'postgres': ")
    conn = psycopg2.connect(
        host="localhost",
        port=5432,
        dbname="cyberpulse360",
        user="postgres",
        password=password,
        connect_timeout=10,
    )
    conn.autocommit = False

    try:
        with conn.cursor() as cur:
            cur.execute(sql.SQL("CREATE SCHEMA IF NOT EXISTS {}").format(sql.Identifier(SCHEMA)))

            row_counts: dict[str, int] = {}
            for table, path in files.items():
                print(f"Loading {table} ...", flush=True)
                columns = get_table_columns(table, path)
                row_counts[table] = create_and_copy_table(cur, table, path, columns)
                print(f"  loaded {row_counts[table]:,} rows | {len(columns)} columns", flush=True)

            print("Creating primary keys, foreign keys and indexes ...", flush=True)
            add_constraints_and_indexes(cur)

            print("Verifying database row counts ...", flush=True)
            for table in files:
                cur.execute(
                    sql.SQL("SELECT COUNT(*) FROM {}.{}").format(
                        sql.Identifier(SCHEMA), sql.Identifier(table)
                    )
                )
                actual = cur.fetchone()[0]
                if actual != row_counts[table]:
                    raise RuntimeError(
                        f"Row count mismatch for {table}: copied={row_counts[table]}, database={actual}"
                    )

        conn.commit()
        print("\n" + "=" * 68)
        print("POSTGRESQL LOAD COMPLETED SUCCESSFULLY")
        print("=" * 68)
        for table, count in row_counts.items():
            print(f"{table}: {count:,} rows")
        print(f"\nDatabase: cyberpulse360")
        print(f"Schema: {SCHEMA}")
        print("Raw files and Power BI CSV outputs were left unchanged.")

    except Exception:
        conn.rollback()
        print("\nLOAD FAILED. Transaction rolled back; database tables remain unchanged.")
        raise
    finally:
        conn.close()


if __name__ == "__main__":
    main()
