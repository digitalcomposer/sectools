"""Inspect a SQLite database and export selected rows to CSV (read-only).

Either hand it a full ``SELECT`` statement, or build one from parts
(``--table``/``--columns``/``--where``/``--order-by``). The database is always
opened read-only, and only read statements are accepted.

Example:
    sectools dbexport --db logins.db --table t_user \
        --columns "id,email,created" --where "status_id = 1" \
        --order-by "id ASC" --out active_users.csv
"""

from __future__ import annotations

import argparse
import csv
import sqlite3
import sys
from pathlib import Path

from sectools.core import report
from sectools.core.evidence import Finding

NAME = "dbexport"
HELP = "inspect a SQLite database and export a filtered, ordered CSV (read-only)"


def connect_readonly(db_path: str | Path) -> sqlite3.Connection:
    """Open ``db_path`` read-only so an analysis can never mutate the evidence."""
    path = Path(db_path)
    if not path.exists():
        raise FileNotFoundError(f"database not found: {path}")
    uri = f"file:{path}?mode=ro"
    return sqlite3.connect(uri, uri=True)


def schema(conn: sqlite3.Connection) -> list[dict[str, str]]:
    """Return ``[{"name", "type", "sql"}]`` for every table and view."""
    cur = conn.execute(
        "SELECT name, type, sql FROM sqlite_master "
        "WHERE type IN ('table', 'view') AND name NOT LIKE 'sqlite_%' "
        "ORDER BY name"
    )
    return [{"name": n, "type": t, "sql": s or ""} for n, t, s in cur.fetchall()]


def _build_query(args: argparse.Namespace) -> str:
    columns = args.columns.strip() if args.columns else "*"
    query = f"SELECT {columns} FROM {args.table}"  # noqa: S608 - table/cols are operator input
    if args.where:
        query += f" WHERE {args.where}"
    if args.order_by:
        query += f" ORDER BY {args.order_by}"
    return query


def _is_read_only(sql: str) -> bool:
    stripped = sql.lstrip().lower()
    return stripped.startswith(("select", "with"))


def run_query(conn: sqlite3.Connection, sql: str) -> tuple[list[str], list[tuple]]:
    """Execute a read-only ``sql`` query and return ``(column_names, rows)``."""
    if not _is_read_only(sql):
        raise ValueError("only SELECT/WITH (read-only) queries are allowed")
    cur = conn.execute(sql)
    headers = [description[0] for description in cur.description]
    return headers, cur.fetchall()


def write_csv(headers: list[str], rows: list[tuple], out: str | Path | None) -> None:
    """Write ``rows`` as CSV to ``out`` (or stdout when ``out`` is None)."""
    if out is None:
        writer = csv.writer(sys.stdout)
        writer.writerow(headers)
        writer.writerows(rows)
        return
    out_path = Path(out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(headers)
        writer.writerows(rows)


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--db", required=True, help="path to the SQLite database file")
    parser.add_argument("--schema", action="store_true", help="print the schema and exit")
    parser.add_argument("--sql", help="full read-only SELECT/WITH statement to run")
    parser.add_argument("--table", help="table to export (when not using --sql)")
    parser.add_argument("--columns", help="comma-separated columns (default: all)")
    parser.add_argument("--where", help="WHERE clause without the 'WHERE' keyword")
    parser.add_argument("--order-by", help="ORDER BY clause without the 'ORDER BY' keyword")
    parser.add_argument("--out", help="output CSV path (default: stdout)")


def run(args: argparse.Namespace) -> Finding:
    conn = connect_readonly(args.db)
    try:
        if args.schema:
            tables = schema(conn)
            md = (
                report.heading("Database schema", 2)
                + "\n\n"
                + report.table(["Name", "Type"], [(t["name"], t["type"]) for t in tables])
            )
            return Finding(
                tool=NAME,
                summary=f"{len(tables)} table(s)/view(s)",
                data={"schema": tables},
                markdown=md,
            )

        if args.sql:
            sql = args.sql
        elif args.table:
            sql = _build_query(args)
        else:
            raise ValueError("provide --schema, --sql, or --table")

        headers, rows = run_query(conn, sql)
        write_csv(headers, rows, args.out)
    finally:
        conn.close()

    md = "\n\n".join(
        [
            report.heading("CSV export", 2),
            report.key_values(
                {
                    "Query": sql,
                    "Columns": ", ".join(headers),
                    "Rows exported": len(rows),
                    "Output": args.out or "stdout",
                }
            ),
        ]
    )
    return Finding(
        tool=NAME,
        summary=f"exported {len(rows)} row(s), {len(headers)} column(s)",
        data={"query": sql, "columns": headers, "row_count": len(rows), "output": args.out},
        markdown=md,
    )
