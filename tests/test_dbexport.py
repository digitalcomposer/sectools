from __future__ import annotations

import csv
import json
import sqlite3

import pytest

from sectools.cli import main
from sectools.tools import dbexport


@pytest.fixture
def sample_db(tmp_path):
    path = tmp_path / "logins.db"
    conn = sqlite3.connect(path)
    conn.executescript(
        """
        CREATE TABLE t_status (id INTEGER PRIMARY KEY, status TEXT);
        INSERT INTO t_status VALUES (1, 'active'), (2, 'locked'), (3, 'unconfirmed');
        CREATE TABLE t_user (id INTEGER PRIMARY KEY, email TEXT, status_id INTEGER);
        INSERT INTO t_user VALUES
            (3, 'c@example.com', 1),
            (1, 'a@example.com', 1),
            (2, 'b@example.com', 2);
        """
    )
    conn.commit()
    conn.close()
    return path


def test_connect_readonly_blocks_writes(sample_db):
    conn = dbexport.connect_readonly(sample_db)
    with pytest.raises(sqlite3.OperationalError):
        conn.execute("INSERT INTO t_status VALUES (9, 'x')")
    conn.close()


def test_schema_lists_tables(sample_db):
    conn = dbexport.connect_readonly(sample_db)
    names = {t["name"] for t in dbexport.schema(conn)}
    conn.close()
    assert names == {"t_status", "t_user"}


def test_run_query_rejects_non_select(sample_db):
    conn = dbexport.connect_readonly(sample_db)
    with pytest.raises(ValueError, match="read-only"):
        dbexport.run_query(conn, "DELETE FROM t_user")
    conn.close()


def test_filtered_ordered_export(sample_db, tmp_path):
    conn = dbexport.connect_readonly(sample_db)
    headers, rows = dbexport.run_query(
        conn,
        "SELECT id, email FROM t_user WHERE status_id = 1 ORDER BY id ASC",
    )
    conn.close()
    out = tmp_path / "active.csv"
    dbexport.write_csv(headers, rows, out)

    with open(out, newline="") as handle:
        read = list(csv.reader(handle))
    assert read[0] == ["id", "email"]
    assert read[1:] == [["1", "a@example.com"], ["3", "c@example.com"]]


def test_cli_schema(sample_db, capsys):
    rc = main(["dbexport", "--db", str(sample_db), "--schema", "--json"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    names = {t["name"] for t in payload["data"]["schema"]}
    assert names == {"t_status", "t_user"}


def test_cli_table_export(sample_db, tmp_path):
    out = tmp_path / "active.csv"
    rc = main(
        [
            "dbexport",
            "--db",
            str(sample_db),
            "--table",
            "t_user",
            "--columns",
            "id,email",
            "--where",
            "status_id = 1",
            "--order-by",
            "id ASC",
            "--out",
            str(out),
        ]
    )
    assert rc == 0
    rows = out.read_text().splitlines()
    assert rows[0] == "id,email"
    assert rows[1:] == ["1,a@example.com", "3,c@example.com"]


def test_cli_missing_selector_errors(sample_db):
    assert main(["dbexport", "--db", str(sample_db)]) == 2
