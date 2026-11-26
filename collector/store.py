import json

from diagnosis import nic_inventory
from pathbuilder import EventLinker
from pathbuilder.events import normalize_event


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def register(db, session, manifest, agents, clocks_aligned):
    EventLinker(manifest["probe_ids"])
    nic_inventory(manifest["vm_nics"])
    if not agents or len(set(agents)) != len(agents) or not all(agents):
        raise ValueError("supply the distinct device IDs of the reporting agents")
    manifest = {"probe_ids": manifest["probe_ids"], "vm_nics": manifest["vm_nics"],
                "agents": sorted(agents), "clocks_aligned": clocks_aligned}
    with db:
        db.execute("CREATE TABLE IF NOT EXISTS session (id TEXT PRIMARY KEY, manifest TEXT NOT NULL)")
        db.execute("""CREATE TABLE IF NOT EXISTS event (session TEXT NOT NULL, probe TEXT NOT NULL,
                   seq INTEGER NOT NULL, body TEXT NOT NULL, PRIMARY KEY (session, probe, seq))""")
        db.execute("""CREATE TABLE IF NOT EXISTS finished (session TEXT NOT NULL, agent TEXT NOT NULL,
                   PRIMARY KEY (session, agent))""")
        db.execute("INSERT INTO session VALUES (?, ?) ON CONFLICT(id) DO NOTHING", (session, encode(manifest)))
        if read_manifest(db, session) != manifest:
            raise ValueError("this session ID already has a different manifest")


def read_manifest(db, session):
    row = db.execute("SELECT manifest FROM session WHERE id=?", (session,)).fetchone()
    if row is None:
        raise ValueError(f"unknown session {session!r}")
    return json.loads(row[0])


def ingest(db, session, agent, source):
    manifest = read_manifest(db, session)
    probes = set(manifest["probe_ids"])
    if agent not in manifest["agents"]:
        raise ValueError("unregistered agent")
    end = False
    for line in source:
        if len(line) > 65536:
            raise ValueError("oversized event")
        raw = json.loads(line)
        if end:
            raise ValueError("unexpected data after end of stream")
        if raw == {"stream_end": True}:
            end = True
            continue
        event = normalize_event(raw)
        if event["phy_device_ID"] != agent:
            raise ValueError("event device does not match reporting agent")
        if event["probe_ID"] not in probes:
            continue
        key = (session, str(event["probe_ID"]), event["sequence_num"])
        body = encode(event)
        with db:
            db.execute("BEGIN IMMEDIATE")
            old = db.execute("SELECT body FROM event WHERE session=? AND probe=? AND seq=?", key).fetchone()
            if old:
                if old[0] != body:
                    raise ValueError("conflicting events with the same probe ID and sequence number")
                continue
            if db.execute("SELECT 1 FROM finished WHERE session=? AND agent=?", (session, agent)).fetchone():
                raise ValueError("agent already finished this session")
            db.execute("INSERT INTO event VALUES (?, ?, ?, ?)", (*key, body))
    if not end:
        raise ValueError("agent stream interrupted; retained events can be replayed")
    with db:
        db.execute("INSERT OR IGNORE INTO finished VALUES (?, ?)", (session, agent))


def recording(db, session):
    with db:
        db.execute("BEGIN")
        manifest = read_manifest(db, session)
        finished = {r[0] for r in db.execute("SELECT agent FROM finished WHERE session=?", (session,))}
        rows = db.execute("SELECT body FROM event WHERE session=? ORDER BY probe, seq", (session,))
        return {"trial_id": session, "probe_ids": manifest["probe_ids"], "vm_nics": manifest["vm_nics"],
                "clocks_aligned": manifest["clocks_aligned"], "capture_complete": finished == set(manifest["agents"]),
                "pending_agents": sorted(set(manifest["agents"]) - finished), "events": [json.loads(r[0]) for r in rows]}
