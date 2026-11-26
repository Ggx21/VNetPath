import argparse
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import sys

from vnetpath import analyze
from .store import ingest, recording, register


def main():
    parser = argparse.ArgumentParser(description="Receive and join VNetPath events from host agents.")
    parser.add_argument("--database", type=Path, required=True)
    commands = parser.add_subparsers(dest="command", required=True)
    plan = commands.add_parser("register", help="register the probe manifest before starting collection")
    plan.add_argument("session")
    plan.add_argument("manifest", type=Path)
    plan.add_argument("--agent", action="append", required=True, help="one expected device ID; repeat per host")
    plan.add_argument("--clocks-aligned", action="store_true", help="host clocks are synchronized")
    receive = commands.add_parser("receive", help="ingest one host stream from standard input")
    receive.add_argument("session")
    receive.add_argument("agent")
    commands.add_parser("export").add_argument("session")
    diag = commands.add_parser("diagnose")
    diag.add_argument("session")
    diag.add_argument("--delay-threshold-ms", type=int, default=100)
    args = parser.parse_args()
    try:
        with closing(sqlite3.connect(args.database, timeout=30)) as db:
            if args.command == "register":
                db.execute("PRAGMA journal_mode=WAL")
                manifest = json.loads(args.manifest.read_text(encoding="utf-8-sig"))
                register(db, args.session, manifest, args.agent, args.clocks_aligned)
            elif args.command == "receive":
                ingest(db, args.session, args.agent, sys.stdin.buffer)
            else:
                document = {"recordings": [recording(db, args.session)]}
                if args.command == "diagnose":
                    document["delay_threshold_ms"] = args.delay_threshold_ms
                    document = analyze(document)
                print(json.dumps(document, indent=2))
    except (OSError, KeyError, ValueError, TypeError, sqlite3.Error) as error:
        parser.exit(2, f"{parser.prog}: {error}\n")


if __name__ == "__main__":
    main()
