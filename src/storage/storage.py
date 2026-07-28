import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path


class FileStorage:
    def __init__(self, base_dir: str = "data"):
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def _path(self, rel_path: str) -> Path:
        path = self.base_dir / rel_path
        path.parent.mkdir(parents=True, exist_ok=True)
        return path

    def read_json(self, rel_path: str, default=None):
        path = self._path(rel_path)
        if not path.exists():
            return default
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)

    def write_json(self, rel_path: str, data):
        path = self._path(rel_path)
        with path.open("w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2)

    def append_audit(self, event: dict):
        events = self.read_json("audit_log.json", [])
        previous_hash = events[-1].get("event_hash", "GENESIS") if events else "GENESIS"
        chained_event = dict(event)
        chained_event["previous_hash"] = previous_hash
        chained_event["event_hash"] = self._audit_hash(chained_event)
        events.append(chained_event)
        self.write_json("audit_log.json", events)
        self.write_json("audit_head.json", {"event_count": len(events), "event_hash": chained_event["event_hash"]})

    def verify_audit_log(self) -> dict:
        events = self.read_json("audit_log.json", [])
        expected_previous = "GENESIS"
        for index, event in enumerate(events):
            if event.get("previous_hash") != expected_previous:
                return {"valid": False, "event_count": len(events), "invalid_index": index}
            expected_hash = self._audit_hash(event)
            if event.get("event_hash") != expected_hash:
                return {"valid": False, "event_count": len(events), "invalid_index": index}
            expected_previous = event["event_hash"]
        head = self.read_json("audit_head.json")
        if not events and head and head.get("event_count", 0) != 0:
            return {"valid": False, "event_count": 0, "invalid_index": 0}
        if events and (
            not head
            or head.get("event_count") != len(events)
            or head.get("event_hash") != expected_previous
        ):
            return {"valid": False, "event_count": len(events), "invalid_index": len(events)}
        return {"valid": True, "event_count": len(events), "invalid_index": None}

    @staticmethod
    def _audit_hash(event: dict) -> str:
        payload = {key: value for key, value in event.items() if key != "event_hash"}
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    @staticmethod
    def now_iso() -> str:
        return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
