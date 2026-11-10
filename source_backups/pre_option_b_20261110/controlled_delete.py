"""Fail-closed controlled deletion. No network or database work at module import.

The backend module is injected so each offline application has isolated models,
configuration and security helpers. All external effects remain explicit methods.
"""
import json
import os
import re
import secrets
import time
from contextlib import contextmanager

import requests
from flask import abort
from sqlalchemy.exc import IntegrityError


def register_models(db):
    class SourceRecord(db.Model):
        id = db.Column(db.String(64), primary_key=True)
        tenant = db.Column(db.String(512), nullable=False)
        app_id = db.Column(db.Integer, nullable=False)
        record_id = db.Column(db.String(32), nullable=False)
        employee = db.Column(db.String(150), nullable=False)
        generation = db.Column(db.String(64), nullable=False)
        revision = db.Column(db.String(32), nullable=False)
        busy = db.Column(db.String(64))
        active_operation = db.Column(db.String(64))

    class EventMapping(db.Model):
        id = db.Column(db.String(64), primary_key=True)
        source_id = db.Column(db.String(64), db.ForeignKey("source_record.id"), nullable=False, index=True)
        tenant = db.Column(db.String(512), nullable=False)
        app_id = db.Column(db.Integer, nullable=False)
        record_id = db.Column(db.String(32), nullable=False)
        row_id = db.Column(db.String(32), nullable=False)
        employee = db.Column(db.String(150), nullable=False, index=True)
        google_sub = db.Column(db.String(255), nullable=False)
        destination = db.Column(db.String(32), nullable=False)
        event_id = db.Column(db.String(1024), nullable=False)
        generation = db.Column(db.String(64), nullable=False)
        revision = db.Column(db.String(32), nullable=False)
        state = db.Column(db.String(32), nullable=False, default="ACTIVE")
        updated_at = db.Column(db.Float, nullable=False, default=time.time)
        __table_args__ = (db.UniqueConstraint("employee", "google_sub", "destination", "event_id"),)

    class RecordDeletion(db.Model):
        id = db.Column(db.String(64), primary_key=True)
        source_id = db.Column(db.String(64), db.ForeignKey("source_record.id"), nullable=False, index=True)
        employee = db.Column(db.String(150), nullable=False, index=True)
        google_sub = db.Column(db.String(255), nullable=False)
        destination = db.Column(db.String(32), nullable=False)
        generation = db.Column(db.String(64), nullable=False)
        revision = db.Column(db.String(32), nullable=False)
        sid_hash = db.Column(db.String(64), nullable=False)
        connection_version = db.Column(db.String(64), nullable=False)
        state = db.Column(db.String(32), nullable=False)
        manifest = db.Column(db.Text, nullable=False)
        manifest_hash = db.Column(db.String(64), nullable=False)
        snapshot_hash = db.Column(db.String(64), nullable=False)
        created_at = db.Column(db.Float, nullable=False)
        expires_at = db.Column(db.Float, nullable=False)
        attempted_at = db.Column(db.Float)
        confirmed_at = db.Column(db.Float)
        evidence = db.Column(db.Text)

    class EventCleanup(db.Model):
        id = db.Column(db.String(64), primary_key=True)
        mapping_id = db.Column(db.String(64), db.ForeignKey("event_mapping.id"), nullable=False, index=True)
        operation_id = db.Column(db.String(64), db.ForeignKey("record_deletion.id"), index=True)
        state = db.Column(db.String(32), nullable=False)
        event_etag = db.Column(db.String(512), nullable=False)
        updated_at = db.Column(db.Float, nullable=False, default=time.time)

    return SourceRecord, EventMapping, RecordDeletion, EventCleanup


class ControlledDeletion:
    ROW_FIELDS = ("row_type", "row_status", "row_place", "row_from", "row_to",
                  "row_start_time", "row_end_time", "row_timezone_select")

    def __init__(self, backend):
        self.b = backend
        for name, default in (
            ("KINTONE_IDENTITY_APP_ID", ""), ("KINTONE_IDENTITY_USER_FIELD", ""),
            ("KINTONE_CONTROLLED_DELETE_ENABLED", "false"),
            ("KINTONE_CONTROLLED_DELETE_PERMISSIONS_ACK", "false"),
            ("KINTONE_DELETE_API_TOKEN", ""),
        ):
            backend.app.config[name] = os.environ.get(name, default)

    @staticmethod
    def field(record, name):
        if (not isinstance(record, dict) or not isinstance(record.get(name), dict)
                or "value" not in record[name]):
            raise ValueError("Missing or incomplete Kintone field: " + name)
        return record[name]["value"]

    @staticmethod
    def identifier(value):
        if not isinstance(value, str) or not re.fullmatch(r"[1-9][0-9]{0,19}", value):
            raise ValueError("Invalid Kintone identifier.")
        return value

    def record_owner(self, record, field="employee"):
        users = self.field(record, field)
        if (not isinstance(users, list) or len(users) != 1 or not isinstance(users[0], dict)
                or not isinstance(users[0].get("code"), str) or not users[0]["code"].strip()):
            raise ValueError("Cannot establish one Kintone employee identity.")
        return users[0]["code"]

    def validate_record(self, record, employee):
        if self.record_owner(record) != employee:
            raise ValueError("Kintone employee identity mismatch. Synchronization stopped.")
        self.identifier(self.field(record, "$id"))
        self.identifier(self.field(record, "$revision"))
        table = self.field(record, "schedule")
        if not isinstance(table, list):
            raise ValueError("Incomplete Kintone schedule table.")
        seen = set()
        for row in table:
            row_id = self.identifier(row.get("id") if isinstance(row, dict) else None)
            if row_id in seen:
                raise ValueError("Duplicate row ID")
            seen.add(row_id)
            values = row.get("value")
            for name in self.ROW_FIELDS:
                if not isinstance(self.field(values, name), str):
                    raise ValueError("Invalid Kintone schedule field: " + name)
            if not self.field(values, "row_type").strip():
                raise ValueError("Incomplete Kintone row type.")
        return record

    def validate_records(self, records, employee):
        if not isinstance(records, list):
            raise ValueError("Incomplete Kintone records retrieval.")
        seen = set()
        for record in records:
            self.validate_record(record, employee)
            record_id = self.field(record, "$id")
            if record_id in seen:
                raise ValueError("Duplicate Kintone record ID.")
            seen.add(record_id)
            source = self.b.db.session.get(self.b.SourceRecord, self.source_id(record_id))
            if source and source.employee != employee:
                raise ValueError("Record ownership changed; independent review required.")

    def identity_settings(self):
        config = self.b.app.config
        app_id, field = config["KINTONE_IDENTITY_APP_ID"], config["KINTONE_IDENTITY_USER_FIELD"]
        if not app_id and not field:
            return None
        self.identifier(str(app_id))
        if (not isinstance(field, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", field)
                or str(app_id) == str(self.b.APP_ID)):
            raise ValueError("Invalid or incomplete employee identity app configuration.")
        return int(app_id), field

    def identity(self, access_token):
        settings = self.identity_settings()
        if settings is None:
            return None
        app_id, field = settings
        records = self.b.kintone_records(access_token, field + " in (LOGINUSER())", app_id=app_id)
        if not isinstance(records, list) or len(records) != 1:
            raise ValueError("Employee identity app must return exactly one protected identity.")
        return self.record_owner(records[0], field)

    def verify_identity(self, row):
        owner = self.identity(self.b.kintone_token(row))
        if owner != row.user_code:
            raise ValueError("Employee identity verification failed.")

    def require_zero_record_cleanup(self, row):
        if self.identity_settings() is None:
            raise ValueError("No accessible employee records. Deletion blocked.")
        self.verify_identity(row)
        operations = self.operations(row.user_code)
        if not operations or any(op.state != "CONFIRMED" for op in operations):
            raise ValueError("Zero records require confirmed record deletion evidence.")

    def source_id(self, record_id):
        return self.hash([self.b.KINTONE, self.b.APP_ID, self.identifier(record_id)])

    def hash(self, value):
        return self.b.digest(json.dumps(value, sort_keys=True, separators=(",", ":")))

    def source(self, record, employee):
        self.validate_record(record, employee)
        record_id = self.field(record, "$id")
        source_id = self.source_id(record_id)
        source = self.b.db.session.get(self.b.SourceRecord, source_id, populate_existing=True)
        if source is None:
            source = self.b.SourceRecord(id=source_id, tenant=self.b.KINTONE, app_id=self.b.APP_ID,
                record_id=record_id, employee=employee, generation=secrets.token_hex(32),
                revision=self.field(record, "$revision"))
            self.b.db.session.add(source)
            try:
                self.b.db.session.commit()
            except IntegrityError:
                self.b.db.session.rollback()
                source = self.b.db.session.get(self.b.SourceRecord, source_id, populate_existing=True)
        if source.employee != employee:
            raise ValueError("Record ownership changed; independent review required.")
        return source

    @contextmanager
    def source_guard(self, source_id):
        b = self.b
        owner = secrets.token_hex(32)
        acquired = b.SourceRecord.query.filter_by(id=source_id, busy=None).update(
            {"busy": owner}, synchronize_session=False)
        b.db.session.commit()
        if acquired != 1:
            abort(409, "Source record is busy or requires recovery.")
        try:
            yield b.db.session.get(b.SourceRecord, source_id, populate_existing=True)
        finally:
            b.db.session.rollback()
            b.SourceRecord.query.filter_by(id=source_id, busy=owner).update(
                {"busy": None}, synchronize_session=False)
            b.db.session.commit()

    def bindings(self, employee):
        security = self.b.security_for(employee)
        if not security.google_sub:
            raise ValueError("Verified Google identity required.")
        return security.google_sub, "primary"

    def parse_key(self, key):
        if not isinstance(key, str):
            raise ValueError("Invalid Google source key.")
        parts = key.split(":")
        if len(parts) != 3 or parts[0] != str(self.b.APP_ID):
            raise ValueError("Invalid Google source key.")
        return self.identifier(parts[1]), self.identifier(parts[2])

    def operations(self, employee):
        return self.b.RecordDeletion.query.join(self.b.SourceRecord).filter(
            self.b.SourceRecord.tenant == self.b.KINTONE,
            self.b.SourceRecord.app_id == self.b.APP_ID,
            self.b.RecordDeletion.employee == employee,
            self.b.RecordDeletion.state.in_(("PREPARED", "UNKNOWN", "CONFIRMED"))).all()

    def check_mapping(self, mapping, source, employee):
        subject, destination = self.bindings(employee)
        if (source is None or mapping.source_id != source.id or mapping.tenant != self.b.KINTONE
                or mapping.app_id != self.b.APP_ID or mapping.record_id != source.record_id
                or mapping.employee != employee or source.employee != employee
                or mapping.google_sub != subject or mapping.destination != destination
                or mapping.generation != source.generation):
            raise ValueError("Event mapping ownership or destination conflict.")

    def check_event(self, event, key, employee, event_id=None):
        private = event.get("extendedProperties", {}).get("private", {}) if isinstance(event, dict) else {}
        if (not isinstance(event, dict) or not isinstance(event.get("id"), str)
                or not event["id"] or (event_id is not None and event["id"] != event_id)
                or not isinstance(event.get("etag"), str) or not event["etag"]
                or private.get(self.b.SCOPE_TAG) != employee or private.get("kintoneKey") != key
                or private.get("kintoneTenant", self.b.KINTONE) != self.b.KINTONE):
            raise ValueError("Google event ownership, identity or version mismatch.")
        return event

    def exact_record(self, row, record_id, service=False):
        b = self.b
        headers = ({"X-Cybozu-API-Token": b.app.config["KINTONE_DELETE_API_TOKEN"]} if service
                   else {"Authorization": "Bearer " + b.kintone_token(row)})
        response = b.requests.get(b.KINTONE + "/k/v1/record.json", headers=headers,
            params={"app": b.APP_ID, "id": self.identifier(record_id)},
            timeout=25, allow_redirects=False)
        response.raise_for_status()
        if response.status_code != 200 or response.headers.get("X-Cybozu-Warning"):
            raise ValueError("Incomplete exact Kintone record response.")
        payload = response.json()
        record = payload.get("record") if isinstance(payload, dict) else None
        self.validate_record(record, row.user_code)
        if self.field(record, "$id") != record_id:
            raise ValueError("Exact Kintone record ID mismatch.")
        return record

    def require_enabled(self):
        config = self.b.app.config
        if str(config["KINTONE_CONTROLLED_DELETE_ENABLED"]).lower() != "true":
            abort(404)
        if (str(config["KINTONE_CONTROLLED_DELETE_PERMISSIONS_ACK"]).lower() != "true"
                or not config["KINTONE_DELETE_API_TOKEN"] or self.identity_settings() is None):
            abort(503, "Controlled deletion requires approved identity, credential and permission configuration.")

    def manifest(self, row, source, record, service):
        """Full calendar scan detects keyed legacy/foreign/duplicate events too.

        No prefix search exists for private extended properties. Records must be
        bootstrapped by a normal confirmed sync before whole-record deletion.
        """
        b = self.b
        mappings = b.EventMapping.query.filter_by(source_id=source.id).all()
        by_event = {}
        keys = set()
        for mapping in mappings:
            self.check_mapping(mapping, source, row.user_code)
            key = f"{b.APP_ID}:{source.record_id}:{mapping.row_id}"
            if key in keys or mapping.event_id in by_event:
                raise ValueError("Conflicting event mappings.")
            keys.add(key)
            by_event[mapping.event_id] = mapping
        manifest = []
        seen = set()
        for event in b.google_events(service, None):
            private = event.get("extendedProperties", {}).get("private", {})
            key = private.get("kintoneKey", "")
            parts = key.split(":") if isinstance(key, str) else []
            if len(parts) < 2 or parts[:2] != [str(b.APP_ID), source.record_id]:
                continue
            self.parse_key(key)
            self.check_event(event, key, row.user_code)
            mapping = by_event.get(event["id"])
            if (mapping is None or mapping.row_id != parts[2] or mapping.state != "ACTIVE"
                    or event["id"] in seen):
                raise ValueError("Unclear event mapping; complete normal sync or independent review first.")
            seen.add(event["id"])
            manifest.append(self.mapping_entry(mapping))
        if any(m.state == "ACTIVE" and m.event_id not in seen for m in mappings):
            raise ValueError("Managed event missing from complete calendar retrieval.")
        # A current eligible row without a managed mapping cannot silently vanish.
        active_keys = {f"{b.APP_ID}:{source.record_id}:{m.row_id}" for m in mappings if m.state == "ACTIVE"}
        for subrow in self.field(record, "schedule"):
            desired = b.row_event(record, subrow, row.user_code)
            if desired and desired["extendedProperties"]["private"]["kintoneKey"] not in active_keys:
                raise ValueError("Synchronize current rows before deleting the monthly record.")
        return sorted(manifest, key=lambda item: item["mapping_id"])

    @staticmethod
    def mapping_entry(mapping):
        return {"mapping_id": mapping.id, "event_id": mapping.event_id, "row_id": mapping.row_id,
                "revision": mapping.revision, "generation": mapping.generation}

    def prepare(self, row, record_id):
        b = self.b
        self.verify_identity(row)
        record = self.exact_record(row, record_id)
        source = self.source(record, row.user_code)
        with self.source_guard(source.id) as source:
            if source.active_operation:
                previous = b.db.session.get(b.RecordDeletion, source.active_operation)
                if previous is None or previous.state != "PREPARED" or previous.expires_at > time.time():
                    abort(409, "Record already has a pending or confirmed deletion operation.")
                previous.state = "EXPIRED"
            service = b.google_service(row)
            if service is None:
                abort(403)
            subject, destination = self.bindings(row.user_code)
            manifest = self.manifest(row, source, record, service)
            security = b.security_for(row.user_code)
            operation = b.RecordDeletion(id=secrets.token_hex(32), source_id=source.id,
                employee=row.user_code, google_sub=subject, destination=destination,
                generation=source.generation, revision=self.field(record, "$revision"),
                sid_hash=b.require_current_browser().sid_hash, connection_version=security.version,
                state="PREPARED", manifest=json.dumps(manifest, sort_keys=True),
                manifest_hash=self.hash(manifest), snapshot_hash=self.hash(record),
                created_at=time.time(), expires_at=time.time() + 300)
            b.db.session.add(operation)
            source.revision = operation.revision
            source.active_operation = operation.id
            b.invalidate_approvals(row.user_code)
            b.db.session.commit()
            return operation

    def execute(self, row, record_id, operation_id):
        b = self.b
        source_id = self.source_id(record_id)
        with self.source_guard(source_id) as source:
            op = b.db.session.get(b.RecordDeletion, operation_id, populate_existing=True)
            subject, destination = self.bindings(row.user_code)
            if (op is None or source.employee != row.user_code or op.employee != row.user_code
                    or op.source_id != source_id or source.active_operation != op.id
                    or op.sid_hash != b.require_current_browser().sid_hash
                    or op.connection_version != b.security_for(row.user_code).version
                    or op.google_sub != subject or op.destination != destination):
                abort(409, "Deletion operation identity or session mismatch.")
            if op.state in ("CONFIRMED", "UNKNOWN"):
                return op  # Replay never dispatches DELETE again.
            if op.state != "PREPARED" or op.expires_at <= time.time():
                abort(409, "Deletion operation expired or already used.")
            self.verify_identity(row)
            record = self.exact_record(row, record_id)
            trusted_record = self.exact_record(row, record_id, service=True)
            service = b.google_service(row)
            if service is None:
                abort(403)
            if (self.hash(record) != op.snapshot_hash or self.hash(trusted_record) != op.snapshot_hash
                    or self.hash(self.manifest(row, source, record, service)) != op.manifest_hash):
                abort(409, "Record or mapping changed. Prepare a new deletion after review.")
            # Persist uncertainty BEFORE dispatch: process death cannot leave a
            # replayable PREPARED operation after an external DELETE succeeded.
            op.state = "UNKNOWN"
            op.attempted_at = time.time()
            b.invalidate_approvals(row.user_code)
            b.db.session.commit()
            try:
                response = b.requests.delete(b.KINTONE + "/k/v1/records.json",
                    headers={"X-Cybozu-API-Token": b.app.config["KINTONE_DELETE_API_TOKEN"]},
                    json={"app": b.APP_ID, "ids": [record_id], "revisions": [op.revision]},
                    timeout=25, allow_redirects=False)
                # The documented successful response is HTTP 200 with {}.
                if (response.status_code != 200 or response.headers.get("X-Cybozu-Warning")
                        or response.json() != {}):
                    return op
            except (requests.RequestException, ValueError):
                return op
            op.state = "CONFIRMED"
            op.confirmed_at = time.time()
            op.evidence = json.dumps({"kind": "revision_checked_delete_success", "http_status": 200,
                "request_hash": self.hash([b.KINTONE, b.APP_ID, record_id, op.revision, op.id])})
            for entry in json.loads(op.manifest):
                b.db.session.add(b.EventCleanup(id=self.hash([op.id, entry["mapping_id"]]),
                    mapping_id=entry["mapping_id"], operation_id=op.id, state="PENDING", event_etag=""))
            b.invalidate_approvals(row.user_code)
            b.db.session.commit()
            return op

    def validated_tombstone(self, op, row):
        b = self.b
        source = b.db.session.get(b.SourceRecord, op.source_id, populate_existing=True)
        subject, destination = self.bindings(row.user_code)
        manifest = json.loads(op.manifest)
        if (op.state != "CONFIRMED" or not op.confirmed_at or not op.attempted_at or not op.evidence
                or op.attempted_at < op.created_at or op.confirmed_at < op.attempted_at
                or source is None or source.tenant != b.KINTONE or source.app_id != b.APP_ID
                or source.employee != row.user_code or op.employee != row.user_code
                or op.google_sub != subject or op.destination != destination
                or source.generation != op.generation or source.active_operation != op.id
                or self.hash(manifest) != op.manifest_hash):
            raise ValueError("Invalid confirmed deletion evidence or ownership.")
        evidence = json.loads(op.evidence)
        if evidence != {"kind": "revision_checked_delete_success", "http_status": 200,
                "request_hash": self.hash([b.KINTONE, b.APP_ID, source.record_id, op.revision, op.id])}:
            raise ValueError("Invalid confirmed deletion receipt.")
        for entry in manifest:
            mapping = b.db.session.get(b.EventMapping, entry["mapping_id"], populate_existing=True)
            if mapping is None:
                raise ValueError("Deletion manifest mapping missing.")
            self.check_mapping(mapping, source, row.user_code)
            if self.mapping_entry(mapping) != entry:
                raise ValueError("Deletion manifest mapping changed.")
            cleanup = b.db.session.get(b.EventCleanup, self.hash([op.id, mapping.id]), populate_existing=True)
            if cleanup is None or cleanup.operation_id != op.id or cleanup.mapping_id != mapping.id:
                raise ValueError("Deletion cleanup evidence missing.")
            if (cleanup.state not in ("PENDING", "UNKNOWN", "DONE")
                    or mapping.state not in ("ACTIVE", "DELETED")
                    or (cleanup.state == "DONE") != (mapping.state == "DELETED")):
                raise ValueError("Deletion cleanup progress conflicts with mapping state.")
        return source, manifest

    def extend_plan(self, row, service, records, actions, existing):
        b = self.b
        records_by_id = {self.field(r, "$id"): r for r in records}
        operations = self.operations(row.user_code)
        tombstones = {}
        for op in operations:
            source = b.db.session.get(b.SourceRecord, op.source_id)
            if source.record_id in records_by_id:
                raise ValueError("Deletion pending, uncertain, or deleted record reappeared.")
            if op.state == "CONFIRMED":
                self.validated_tombstone(op, row)
                tombstones[source.record_id] = op
            else:
                raise ValueError("Record deletion pending or uncertain; review required.")
        for action in actions:
            record_id, row_id = self.parse_key(action["key"])
            record = records_by_id.get(record_id)
            current = existing.get(action["key"])
            source = b.db.session.get(b.SourceRecord, self.source_id(record_id))
            if source and source.employee != row.user_code:
                raise ValueError("Record ownership changed; independent review required.")
            mapping = b.db.session.get(b.EventMapping, self.hash([self.source_id(record_id), row_id]))
            if mapping:
                self.check_mapping(mapping, source, row.user_code)
                if action["eventId"] and mapping.event_id != action["eventId"]:
                    raise ValueError("Google event differs from durable mapping.")
                if mapping.state == "DELETED":
                    raise ValueError("Previously deleted mapping reappeared; review required.")
            action["source_revision"] = self.field(record, "$revision") if record else None
            action["source_generation"] = source.generation if source else None
            action["event_etag"] = current.get("etag") if current else None
            if record:
                action["source_hash"] = self.hash(record)
            if action["action"] == "BLOCKED" and record_id in tombstones:
                op = tombstones[record_id]
                if not mapping or self.mapping_entry(mapping) not in json.loads(op.manifest):
                    raise ValueError("Event is not in confirmed deletion manifest.")
                self.check_event(current, action["key"], row.user_code, mapping.event_id)
                action.update(action="DELETE", reason="Confirmed monthly record deletion",
                    deletion_operation=op.id, manifest_hash=op.manifest_hash)
            if action["action"] == "DELETE" and current:
                self.check_event(current, action["key"], row.user_code, action["eventId"])
            elif current and action["action"] in ("UPDATE", "UNCHANGED"):
                private = current.get("extendedProperties", {}).get("private", {})
                if private.get("kintoneTenant", b.KINTONE) != b.KINTONE:
                    raise ValueError("Google event belongs to a different Kintone tenant.")
            if mapping:
                cleanup = b.db.session.get(b.EventCleanup,
                    self.hash([action.get("deletion_operation") or "row", mapping.id]))
                action["cleanup_evidence"] = self.cleanup_evidence(cleanup)
        # A missing managed event is not silently counted as a completed deletion.
        for mapping in b.EventMapping.query.filter_by(tenant=b.KINTONE, app_id=b.APP_ID,
                employee=row.user_code, state="ACTIVE").all():
            self.check_mapping(mapping, b.db.session.get(b.SourceRecord, mapping.source_id), row.user_code)
            key = f"{b.APP_ID}:{mapping.record_id}:{mapping.row_id}"
            if key not in existing:
                op = tombstones.get(mapping.record_id)
                cleanup = b.db.session.get(b.EventCleanup, self.hash([op.id if op else "row", mapping.id]))
                if cleanup is None or cleanup.state != "UNKNOWN":
                    raise ValueError("Managed Google event missing; review required.")
                # A positive, attributable tombstone may resolve a timed-out
                # Google DELETE. A failed GET or metadata-free 404 cannot.
                cancelled = service.events().get(calendarId="primary", eventId=mapping.event_id).execute()
                self.check_event(cancelled, key, row.user_code, mapping.event_id)
                if cancelled.get("status") != "cancelled":
                    raise ValueError("Incomplete calendar listing; cleanup blocked.")
                record = records_by_id.get(mapping.record_id)
                if not op and (record is None or any(r["id"] == mapping.row_id for r in self.field(record, "schedule"))):
                    raise ValueError("Row cleanup evidence changed.")
                actions.append(dict(action="DELETE", key=key, title="Resolve prior cleanup attempt",
                    eventId=mapping.event_id, body=None, event_etag=cancelled["etag"],
                    cleanup_evidence=self.cleanup_evidence(cleanup),
                    source_revision=self.field(record, "$revision") if record else None,
                    source_hash=self.hash(record) if record else None, source_generation=mapping.generation,
                    **({"deletion_operation": op.id, "manifest_hash": op.manifest_hash} if op else {})))

    @staticmethod
    def cleanup_evidence(cleanup):
        return ([cleanup.id, cleanup.state, cleanup.event_etag, cleanup.updated_at] if cleanup else None)

    def record_mapping(self, row, source, action, event_id, state="ACTIVE"):
        b = self.b
        _, row_id = self.parse_key(action["key"])
        mapping_id = self.hash([source.id, row_id])
        mapping = b.db.session.get(b.EventMapping, mapping_id, populate_existing=True)
        subject, destination = self.bindings(row.user_code)
        if mapping:
            self.check_mapping(mapping, source, row.user_code)
            if mapping.event_id != event_id or mapping.state == "DELETED":
                raise ValueError("Existing mapping conflicts with managed event.")
        else:
            mapping = b.EventMapping(id=mapping_id, source_id=source.id, tenant=b.KINTONE,
                app_id=b.APP_ID, record_id=source.record_id, row_id=row_id, employee=row.user_code,
                google_sub=subject, destination=destination, event_id=event_id,
                generation=source.generation, revision=action["source_revision"], state=state)
            b.db.session.add(mapping)
        mapping.revision = action["source_revision"] or mapping.revision
        mapping.state = state
        mapping.updated_at = time.time()
        source.revision = mapping.revision
        b.db.session.commit()
        return mapping

    def apply_action(self, row, service, action):
        b = self.b
        record_id, _ = self.parse_key(action["key"])
        op_id = action.get("deletion_operation")
        if op_id:
            op = b.db.session.get(b.RecordDeletion, op_id, populate_existing=True)
            if op is None:
                raise ValueError("Deletion evidence missing.")
            source, _ = self.validated_tombstone(op, row)
        else:
            record = self.exact_record(row, record_id)
            if (self.field(record, "$revision") != action.get("source_revision")
                    or self.hash(record) != action.get("source_hash")):
                abort(409, "Source record changed. Refresh preview.")
            source = self.source(record, row.user_code)
        with self.source_guard(source.id) as source:
            if action.get("source_generation") and source.generation != action["source_generation"]:
                abort(409, "Source ownership generation changed. Refresh preview.")
            if op_id:
                self.validated_tombstone(op, row)
            elif source.active_operation:
                abort(409, "Source has a pending deletion operation.")
            operation = action["action"]
            if operation == "CREATE":
                b.create_event(service, action, row.user_code)
                event_id = b.deterministic_event_id(row.user_code, action["key"])
                current = service.events().get(calendarId="primary", eventId=event_id).execute()
                self.check_event(current, action["key"], row.user_code, event_id)
                if current.get("status") == "cancelled" or not b.equal_event(current, action["body"]):
                    raise ValueError("Created Google event could not be verified.")
                self.record_mapping(row, source, action, event_id)
                return
            current = service.events().get(calendarId="primary", eventId=action["eventId"]).execute()
            # Preserve existing reviewed legacy adoption only for a visible row;
            # unowned legacy events can never participate in deletion.
            private = current.get("extendedProperties", {}).get("private", {})
            legacy = (operation == "UPDATE" and private.get(b.SCOPE_TAG) is None
                      and not op_id and b.GoogleQuarantine.query.first() is None)
            if legacy:
                current = dict(current, extendedProperties={"private": dict(private, **{b.SCOPE_TAG: row.user_code})})
            self.check_event(current, action["key"], row.user_code, action["eventId"])
            if current["etag"] != action.get("event_etag"):
                abort(409, "Google event changed. Refresh preview.")
            if current.get("status") == "cancelled":
                self.complete_cancelled(row, source, action, current)
                return
            if operation == "UPDATE":
                request = service.events().patch(calendarId="primary", eventId=action["eventId"],
                    body=action["body"], sendUpdates="none")
                request.headers["If-Match"] = current["etag"]
                request.execute()
                updated = service.events().get(calendarId="primary", eventId=action["eventId"]).execute()
                self.check_event(updated, action["key"], row.user_code, action["eventId"])
                if updated.get("status") == "cancelled" or not b.equal_event(updated, action["body"]):
                    raise ValueError("Updated Google event could not be verified.")
                self.record_mapping(row, source, action, action["eventId"])
            elif operation == "UNCHANGED":
                if not b.equal_event(current, action["body"]):
                    abort(409, "Google event changed. Refresh preview.")
                self.record_mapping(row, source, action, action["eventId"])
            elif operation == "DELETE":
                mapping = (b.db.session.get(b.EventMapping, self.hash([source.id, self.parse_key(action["key"])[1]]))
                           if op_id else self.record_mapping(row, source, action, action["eventId"]))
                cleanup_id = self.hash([op_id or "row", mapping.id])
                cleanup = b.db.session.get(b.EventCleanup, cleanup_id)
                if cleanup is None:
                    cleanup = b.EventCleanup(id=cleanup_id, mapping_id=mapping.id,
                        operation_id=op_id, state="PENDING", event_etag=current["etag"])
                    b.db.session.add(cleanup)
                cleanup.state = "UNKNOWN"
                cleanup.event_etag = current["etag"]
                cleanup.updated_at = time.time()
                b.db.session.commit()
                request = service.events().delete(calendarId="primary", eventId=action["eventId"], sendUpdates="none")
                request.headers["If-Match"] = current["etag"]
                request.execute()  # Any exception leaves durable UNKNOWN progress.
                cleanup.state = "DONE"
                cleanup.updated_at = time.time()
                mapping.state = "DELETED"
                b.db.session.commit()
            else:
                raise ValueError("Unsupported sync operation.")

    def complete_cancelled(self, row, source, action, event):
        """Only an attributable cancelled event plus a prior attempt proves cleanup.

        Google may strip tombstone metadata. Such responses require operator
        recovery; a bare 404/410 never proves successful deletion.
        """
        b = self.b
        mapping_id = self.hash([source.id, self.parse_key(action["key"])[1]])
        cleanup = b.db.session.get(b.EventCleanup, self.hash([action.get("deletion_operation") or "row", mapping_id]))
        if action["action"] != "DELETE" or cleanup is None or cleanup.state != "UNKNOWN":
            raise ValueError("Unexpected cancelled Google event; review required.")
        mapping = b.db.session.get(b.EventMapping, mapping_id)
        self.check_mapping(mapping, source, row.user_code)
        cleanup.state = "DONE"
        mapping.state = "DELETED"
        b.db.session.commit()
