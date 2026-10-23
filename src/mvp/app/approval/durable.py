"""Persist the tested state machine within one SQLite transaction per operation."""
import json
from dataclasses import asdict

from app.auth.state_store import transaction


class SQLiteApprovalManager:
    def __init__(self, path, timeout_seconds=300, approved_timeout_seconds=None):
        self.path, self.timeout, self.approved_timeout = path, timeout_seconds, approved_timeout_seconds

    def _invoke(self, method, *args, **kwargs):
        # Import lazily so workflow can choose this manager at module startup.
        from app.approval.workflow import ApprovalManager, ApprovalRecord, ApprovalStatus
        with transaction(self.path) as connection:
            connection.execute("CREATE TABLE IF NOT EXISTS approvals (request_id TEXT PRIMARY KEY, record TEXT NOT NULL)")
            manager = ApprovalManager(self.timeout, self.approved_timeout)
            before = {}
            for rid, data in connection.execute("SELECT request_id, record FROM approvals"):
                values = json.loads(data)
                values["status"] = ApprovalStatus(values["status"])
                record = ApprovalRecord(**values)
                if record.request_id != rid:
                    raise ValueError("Corrupt approval state")
                target = manager._pending if record.status == ApprovalStatus.PENDING else manager._resolved
                target[rid] = record
                before[rid] = json.dumps(asdict(record), sort_keys=True)
            result = getattr(manager, method)(*args, **kwargs)
            for rid, record in (manager._pending | manager._resolved).items():
                data = json.dumps(asdict(record), sort_keys=True)
                if before.get(rid) != data:
                    connection.execute("INSERT INTO approvals VALUES (?, ?) ON CONFLICT(request_id) DO UPDATE SET record=excluded.record", (rid, data))
            return result

    def submit(self, *args, **kwargs):
        return self._invoke("submit", *args, **kwargs)

    def approve(self, *args, **kwargs):
        return self._invoke("approve", *args, **kwargs)

    def reject(self, *args, **kwargs):
        return self._invoke("reject", *args, **kwargs)

    def consume(self, *args, **kwargs):
        return self._invoke("consume", *args, **kwargs)

    def get_status(self, *args, **kwargs):
        return self._invoke("get_status", *args, **kwargs)

    def check_timeouts(self):
        return self._invoke("check_timeouts")

    def list_pending(self):
        return self._invoke("list_pending")

    @property
    def pending_count(self):
        return len(self.list_pending())
