import argparse
import json
import sqlite3
from contextlib import closing
from pathlib import Path

from psycopg.types.json import Jsonb

from .storage import Storage, database_url


def import_sqlite(path: Path, storage: Storage) -> dict[str, int]:
    if not path.is_file():
        raise FileNotFoundError(path)

    storage.initialize(recover_interrupted=False)
    uri = f"{path.resolve().as_uri()}?mode=ro"
    with closing(sqlite3.connect(uri, uri=True)) as source, storage.connect() as target:
        source.execute("BEGIN")
        archives = target.cursor()
        archives.executemany(
            "INSERT INTO sources (id, archive) VALUES (%s, %s) ON CONFLICT (id) DO NOTHING",
            source.execute("SELECT id, archive FROM sources ORDER BY rowid"),
        )
        workflows = target.cursor()
        workflows.executemany(
            "INSERT INTO workflows (id, body) VALUES (%s, %s) ON CONFLICT (id) DO NOTHING",
            ((row_id, Jsonb(json.loads(body))) for row_id, body in source.execute(
                "SELECT id, body FROM workflows ORDER BY rowid"
            )),
        )
        runs = target.cursor()
        runs.executemany(
            "INSERT INTO runs (id, body) VALUES (%s, %s) ON CONFLICT (id) DO NOTHING",
            ((row_id, Jsonb(json.loads(body))) for row_id, body in source.execute("SELECT id, body FROM runs")),
        )
        return {"sources": archives.rowcount, "workflows": workflows.rowcount, "runs": runs.rowcount}


def main():
    parser = argparse.ArgumentParser(description="Import data from the local SQLite prototype into PostgreSQL.")
    parser.add_argument("sqlite_file", type=Path)
    args = parser.parse_args()
    if not args.sqlite_file.is_file():
        parser.error(f"SQLite file not found: {args.sqlite_file}")
    counts = import_sqlite(args.sqlite_file, Storage(database_url()))
    print("Imported " + ", ".join(f"{table}: {count}" for table, count in counts.items()))


if __name__ == "__main__":
    main()
