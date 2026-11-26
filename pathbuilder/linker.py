"""Link unordered, possibly repeated host reports by packet ID and hop sequence."""

from copy import deepcopy

from .events import normalize_event


class EventLinker:
    """Accumulate one replay. Call paths() after all reporting sources have finished."""

    def __init__(self, probe_ids):
        if not isinstance(probe_ids, list) or not probe_ids:
            raise ValueError("probe_ids must list the probes sent")
        self.by_probe = {}
        for probe in probe_ids:
            if type(probe) is not int or not 0 <= probe < 2**64 or probe in self.by_probe:
                raise ValueError(f"invalid or duplicate probe ID: {probe!r}")
            self.by_probe[probe] = {}

    def add(self, event):
        record = normalize_event(event)
        probe, seq = record["probe_ID"], record["sequence_num"]
        if probe not in self.by_probe:
            raise ValueError(f"undeclared probe: {probe!r}")
        records = self.by_probe[probe]
        if seq not in records:
            # An input stream can reuse its decoding buffer for the next event.
            records[seq] = deepcopy(record)
        elif records[seq] != record:
            raise ValueError(f"conflicting records for probe {probe}, sequence {seq}")

    def extend(self, events):
        for event in events:
            self.add(event)

    def paths(self):
        paths = []
        for probe, records in self.by_probe.items():
            # Unique positive sequence numbers are contiguous iff max == count.
            if not records or max(records) != len(records):
                raise ValueError(f"missing events for probe {probe}")
            paths.append([records[seq] for seq in range(1, len(records) + 1)])
        return paths


def index_events(probe_ids, events):
    """Return the original probe -> sequence -> event index without finalizing it."""
    linker = EventLinker(probe_ids)
    linker.extend(events)
    return linker.by_probe
