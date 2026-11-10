"""Controlled-deletion integration tests: disposable databases, fake APIs only."""
import copy
from contextlib import closing
import json
import re
import threading
import sqlite3
import time
import unittest
from unittest.mock import Mock, patch

import requests
from googleapiclient.errors import HttpError
from httplib2 import Response

import test_security as security_tests
import test_timezones as timezone_tests


class ControlledDeletionTests(unittest.TestCase):
    setUp_base = security_tests.SecurityTests.setUp
    dispose = security_tests.SecurityTests.dispose
    login_client = security_tests.SecurityTests.login_client
    record = security_tests.SecurityTests.record
    event = security_tests.SecurityTests.event

    def setUp(self):
        self.setUp_base()
        self.exact_record_patch.stop()
        self.records = {"123": self.record()}
        self.events = {}
        self.cancelled = {}
        self.service = Mock()
        self.mutations = []
        self.delete_requests = []
        self.delete_error = None
        self.patch_helper(self.b, "google_service", return_value=self.service)
        self.patch_helper(self.b, "get_self_records", side_effect=lambda row: copy.deepcopy(list(self.records.values())))
        self.patch_helper(self.b.controlled, "exact_record", side_effect=self.exact)
        self.identity_patch = self.patch_helper(self.b.controlled, "identity", return_value="employee-a")
        self.patch_helper(self.b, "kintone_token", return_value="offline-kintone")
        self.b.app.config.update(KINTONE_IDENTITY_APP_ID="900001",  # Disposable test fixture only.
            KINTONE_IDENTITY_USER_FIELD="TestIdentityUser", KINTONE_DELETE_API_TOKEN="offline-delete-token",
            KINTONE_CONTROLLED_DELETE_PERMISSIONS_ACK="true", KINTONE_CONTROLLED_DELETE_ENABLED="true")
        self.service.events.return_value.list.side_effect = self.list_events
        self.service.events.return_value.get.side_effect = self.get_event
        self.service.events.return_value.insert.side_effect = self.insert_event
        self.service.events.return_value.patch.side_effect = self.patch_event
        self.service.events.return_value.delete.side_effect = self.delete_event
        self.kdelete = self.patch_helper(self.b.requests, "delete", side_effect=self.delete_record)

    def patch_helper(self, target, name, **kwargs):
        patcher = patch.object(target, name, **kwargs)
        mock = patcher.start()
        self.addCleanup(patcher.stop)
        return mock

    def exact(self, row, record_id, service=False):
        if record_id not in self.records:
            raise ValueError("Record inaccessible")
        record = copy.deepcopy(self.records[record_id])
        return self.b.controlled.validate_record(record, row.user_code)

    def request(self, function):
        return Mock(headers={}, execute=Mock(side_effect=function))

    def list_events(self, **kwargs):
        def execute():
            items = list(self.events.values())
            filter_value = kwargs.get("privateExtendedProperty")
            if filter_value:
                name, value = filter_value.split("=", 1)
                items = [e for e in items if e.get("extendedProperties", {}).get("private", {}).get(name) == value]
            return {"items": copy.deepcopy(items)}
        return self.request(execute)

    def get_event(self, **kwargs):
        def execute():
            event_id = kwargs["eventId"]
            event = self.events.get(event_id) or self.cancelled.get(event_id)
            if event is None:
                raise HttpError(Response({"status": "404"}), b'{}')
            return copy.deepcopy(event)
        return self.request(execute)

    def insert_event(self, **kwargs):
        def execute():
            event = dict(copy.deepcopy(kwargs["body"]), etag='"v1"', status="confirmed")
            if event["id"] in self.events:
                raise HttpError(Response({"status": "409"}), b'{}')
            self.events[event["id"]] = event
            self.mutations.append(("CREATE", event["id"]))
            return copy.deepcopy(event)
        return self.request(execute)

    def patch_event(self, **kwargs):
        def execute():
            self.events[kwargs["eventId"]].update(copy.deepcopy(kwargs["body"]))
            self.mutations.append(("UPDATE", kwargs["eventId"]))
            return copy.deepcopy(self.events[kwargs["eventId"]])
        return self.request(execute)

    def delete_event(self, **kwargs):
        def execute():
            if self.delete_error:
                raise self.delete_error
            event = self.events.pop(kwargs["eventId"])
            event["status"] = "cancelled"
            self.cancelled[event["id"]] = event
            self.mutations.append(("DELETE", event["id"]))
            return None
        request = self.request(execute)
        self.delete_requests.append(request)
        return request

    def delete_record(self, *args, **kwargs):
        self.assertEqual(kwargs["json"]["app"], 1675)
        self.assertEqual(kwargs["json"]["revisions"], [self.records["123"]["$revision"]["value"]])
        self.assertFalse(kwargs["allow_redirects"])
        self.records.pop("123")
        return Mock(status_code=200, headers={}, json=Mock(return_value={}))

    def preview(self):
        response = self.client.get("/sync/preview")
        if response.status_code != 200:
            return response, None
        html = response.get_data(as_text=True)
        approval = re.search(r'name="approval" value="([^"]+)"', html)
        fingerprint = re.search(r'name="fingerprint" value="([^"]+)"', html)
        return response, ({"approval": approval.group(1), "fingerprint": fingerprint.group(1),
                           "csrf": "test-csrf"} if approval else None)

    def sync(self):
        response, form = self.preview()
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        self.assertIsNotNone(form)
        response = self.client.post("/sync/apply", data=form)
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))

    def prepare(self):
        response = self.client.post("/records/123/delete/prepare", data={"csrf": "test-csrf"})
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        return response.json["operation_id"]

    def execute(self, operation):
        return self.client.post("/records/123/delete", data={"csrf": "test-csrf", "operation_id": operation})

    def plan(self):
        with self.b.app.app_context():
            return self.b.build_plan(self.b.db.session.get(self.b.Connection, "employee-a"), self.service)[0]

    def test_whole_record_delete_and_zero_record_repeated_sync(self):
        second = timezone_tests.TimezoneTests().row()
        second["id"] = "789"
        self.records["123"]["schedule"]["value"].append(second)
        self.sync()
        self.assertEqual(len(self.events), 2)
        operation = self.prepare()
        self.assertEqual(self.execute(operation).json["state"], "CONFIRMED")
        self.assertEqual(len(self.events), 2)  # Kintone deletion never writes Google.
        self.assertEqual([a["action"] for a in self.plan()], ["DELETE", "DELETE"])
        self.sync()
        self.assertEqual(len(self.events), 0)
        self.sync()
        self.assertEqual(len(self.mutations), 4)
        with self.b.app.app_context():
            self.assertEqual(self.b.EventMapping.query.filter_by(state="DELETED").count(), 2)
            self.assertEqual(self.b.EventCleanup.query.filter_by(state="DONE").count(), 2)
        self.assertEqual(self.execute(operation).json["state"], "CONFIRMED")
        self.assertEqual(self.kdelete.call_count, 1)

    def test_removed_row_deletes_only_matching_event(self):
        second = timezone_tests.TimezoneTests().row()
        second["id"] = "789"
        self.records["123"]["schedule"]["value"].append(second)
        self.sync()
        self.records["123"]["schedule"]["value"].pop()
        self.records["123"]["$revision"]["value"] = "2"
        actions = self.plan()
        self.assertEqual([(a["key"], a["action"]) for a in actions],
                         [("1675:123:456", "UNCHANGED"), ("1675:123:789", "DELETE")])
        self.sync()
        self.assertEqual(len(self.events), 1)

    def test_manifest_includes_previously_synced_removed_rows(self):
        self.sync()
        self.records["123"]["schedule"]["value"] = []
        self.records["123"]["$revision"]["value"] = "2"
        op = self.prepare()
        with self.b.app.app_context():
            self.assertEqual(len(json.loads(self.b.db.session.get(self.b.RecordDeletion, op).manifest)), 1)
        self.assertEqual(self.execute(op).json["state"], "CONFIRMED")
        self.sync()
        self.assertEqual(self.events, {})

    def test_permission_loss_and_uncontrolled_missing_parent_never_delete(self):
        self.sync()
        self.records = {"999": self.record([], record_id="999")}
        response, form = self.preview()
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(form)
        self.assertIn("BLOCKED", response.get_data(as_text=True))
        self.records = {}
        response, form = self.preview()
        self.assertEqual(response.status_code, 502)
        self.assertIsNone(form)
        self.assertEqual(len(self.events), 1)

    def test_unknown_kintone_outcome_and_replay_never_cleanup(self):
        self.sync()
        operation = self.prepare()
        self.kdelete.side_effect = requests.Timeout("ambiguous")
        self.assertEqual(self.execute(operation).json["state"], "UNKNOWN")
        self.records = {}
        self.assertEqual(self.execute(operation).json["state"], "UNKNOWN")
        response, form = self.preview()
        self.assertEqual(response.status_code, 502)
        self.assertIsNone(form)
        self.assertEqual(self.kdelete.call_count, 1)
        self.assertEqual(len(self.events), 1)

    def test_unexpected_kintone_responses_never_confirm(self):
        self.sync()
        operation = self.prepare()
        for response in (Mock(status_code=403, headers={}), Mock(status_code=500, headers={}),
                         Mock(status_code=302, headers={}),
                         Mock(status_code=200, headers={}, json=Mock(return_value={"success": True})),
                         Mock(status_code=200, headers={}, json=Mock(side_effect=ValueError("bad JSON")))):
            with self.subTest(status=response.status_code):
                # Each independent attempt starts from a persisted PREPARED fixture.
                with self.b.app.app_context():
                    op = self.b.db.session.get(self.b.RecordDeletion, operation)
                    op.state = "PREPARED"
                    self.b.db.session.commit()
                self.kdelete.side_effect = None
                self.kdelete.return_value = response
                self.assertEqual(self.execute(operation).json["state"], "UNKNOWN")

    def test_crash_after_dispatch_is_durable_unknown(self):
        self.sync()
        operation = self.prepare()
        def crash(*args, **kwargs):
            self.records = {}
            raise SystemExit("simulated worker death after Kintone accepted")
        self.kdelete.side_effect = crash
        with self.assertRaises(SystemExit):
            self.execute(operation)
        with self.b.app.app_context():
            self.assertEqual(self.b.db.session.get(self.b.RecordDeletion, operation).state, "UNKNOWN")
        self.assertEqual(self.execute(operation).json["state"], "UNKNOWN")
        self.assertEqual(self.kdelete.call_count, 1)

    def test_revision_changed_after_prepare_prevents_dispatch(self):
        self.sync()
        operation = self.prepare()
        self.records["123"]["$revision"]["value"] = "2"
        self.assertEqual(self.execute(operation).status_code, 409)
        self.kdelete.assert_not_called()

    def test_service_snapshot_conflict_prevents_dispatch(self):
        self.sync()
        operation = self.prepare()
        original = self.b.controlled.exact_record.side_effect
        def mismatch(row, record_id, service=False):
            record = original(row, record_id)
            if service:
                record["$revision"]["value"] = "2"
            return record
        self.b.controlled.exact_record.side_effect = mismatch
        self.assertEqual(self.execute(operation).status_code, 409)
        self.kdelete.assert_not_called()

    def test_stale_preview_after_confirmed_deletion(self):
        self.sync()
        _, form = self.preview()
        operation = self.prepare()
        self.execute(operation)
        self.assertEqual(self.client.post("/sync/apply", data=form).status_code, 409)
        self.assertEqual(len(self.events), 1)

    def test_tampered_tombstone_invalidates_preview(self):
        self.sync()
        operation = self.prepare()
        self.execute(operation)
        _, form = self.preview()
        with self.b.app.app_context():
            self.b.db.session.get(self.b.RecordDeletion, operation).manifest_hash = "tampered"
            self.b.db.session.commit()
        self.assertNotEqual(self.client.post("/sync/apply", data=form).status_code, 200)
        self.assertEqual(len(self.events), 1)

    def test_partial_google_failure_can_retry_remaining_events(self):
        second = timezone_tests.TimezoneTests().row()
        second["id"] = "789"
        self.records["123"]["schedule"]["value"].append(second)
        self.sync()
        op = self.prepare()
        self.execute(op)
        original = self.service.events.return_value.delete.side_effect
        count = [0]
        def fail_second(**kwargs):
            count[0] += 1
            if count[0] == 2:
                return self.request(lambda: (_ for _ in ()).throw(HttpError(Response({"status": "503"}), b'{}')))
            return original(**kwargs)
        self.service.events.return_value.delete.side_effect = fail_second
        _, form = self.preview()
        self.assertEqual(self.client.post("/sync/apply", data=form).status_code, 502)
        self.assertEqual(len(self.events), 1)
        self.assertEqual(self.client.post("/sync/apply", data=form).status_code, 409)
        self.service.events.return_value.delete.side_effect = original
        self.sync()
        self.assertEqual(self.events, {})

    def test_google_timeout_after_success_resolves_only_with_attributable_cancelled_event(self):
        self.sync()
        operation = self.prepare()
        self.execute(operation)
        original = self.service.events.return_value.delete.side_effect
        def timeout_after(**kwargs):
            req = original(**kwargs)
            def execute():
                req.execute()
                raise requests.Timeout("response lost")
            return self.request(execute)
        self.service.events.return_value.delete.side_effect = timeout_after
        _, form = self.preview()
        self.assertEqual(self.client.post("/sync/apply", data=form).status_code, 502)
        self.assertEqual(self.events, {})
        self.service.events.return_value.delete.side_effect = original
        self.sync()
        self.assertEqual([m[0] for m in self.mutations], ["CREATE", "DELETE"])

    def test_bare_google_404_never_marks_cleanup_done(self):
        self.sync()
        operation = self.prepare()
        self.execute(operation)
        self.delete_error = requests.Timeout("ambiguous")
        _, form = self.preview()
        self.client.post("/sync/apply", data=form)
        self.events.clear()
        response, form = self.preview()
        self.assertEqual(response.status_code, 502)
        with self.b.app.app_context():
            self.assertEqual(self.b.EventCleanup.query.one().state, "UNKNOWN")

    def test_cross_employee_and_other_session_cannot_delete(self):
        self.sync()
        operation = self.prepare()
        for other in (self.login_client("employee-b", "subject-b"), self.login_client("employee-a", "subject-a")):
            response = other.post("/records/123/delete", data={"csrf": "test-csrf", "operation_id": operation})
            self.assertEqual(response.status_code, 409)
        self.kdelete.assert_not_called()

    def test_reassignment_blocks_new_employee_and_original_employee(self):
        self.sync()
        self.records["123"]["employee"]["value"] = [{"code": "employee-b"}]
        self.assertEqual(self.preview()[0].status_code, 502)
        other = self.login_client("employee-b", "subject-b")
        self.identity_patch.return_value = "employee-b"
        response = other.post("/records/123/delete/prepare", data={"csrf": "test-csrf"})
        self.assertEqual(response.status_code, 400)
        self.kdelete.assert_not_called()

    def test_changed_google_account_blocks_tombstone(self):
        self.sync()
        op = self.prepare()
        self.execute(op)
        with self.b.app.app_context():
            self.b.security_for("employee-a").google_sub = "different-subject"
            self.b.db.session.commit()
        self.assertEqual(self.preview()[0].status_code, 502)
        self.assertEqual(len(self.events), 1)

    def test_unowned_or_duplicate_events_block_prepare(self):
        self.sync()
        original = copy.deepcopy(next(iter(self.events.values())))
        for owner in (None, "employee-b", "employee-a"):
            with self.subTest(owner=owner):
                event = dict(copy.deepcopy(original), id="ambiguous-extra")
                if owner is None:
                    event["extendedProperties"]["private"].pop(self.b.SCOPE_TAG)
                else:
                    event["extendedProperties"]["private"][self.b.SCOPE_TAG] = owner
                self.events["ambiguous-extra"] = event
                self.assertEqual(self.client.post("/records/123/delete/prepare", data={"csrf": "test-csrf"}).status_code, 400)
                self.events.pop("ambiguous-extra")
        self.kdelete.assert_not_called()

    def test_unsynced_record_requires_bootstrap(self):
        self.assertEqual(self.client.post("/records/123/delete/prepare", data={"csrf": "test-csrf"}).status_code, 400)
        self.kdelete.assert_not_called()

    def test_feature_default_and_configuration_fail_closed(self):
        self.b.app.config["KINTONE_CONTROLLED_DELETE_ENABLED"] = "false"
        self.assertEqual(self.client.post("/records/123/delete/prepare", data={"csrf": "test-csrf"}).status_code, 404)
        self.b.app.config["KINTONE_CONTROLLED_DELETE_ENABLED"] = "true"
        for name in ("KINTONE_DELETE_API_TOKEN", "KINTONE_CONTROLLED_DELETE_PERMISSIONS_ACK", "KINTONE_IDENTITY_APP_ID"):
            old = self.b.app.config[name]
            self.b.app.config[name] = ""
            self.assertNotEqual(self.client.post("/records/123/delete/prepare", data={"csrf": "test-csrf"}).status_code, 200)
            self.b.app.config[name] = old
        self.kdelete.assert_not_called()

    def test_csrf_and_authentication_required(self):
        for path in ("/records/123/delete/prepare", "/records/123/delete"):
            self.assertEqual(self.client.post(path, data={}).status_code, 403)
            self.assertEqual(self.b.app.test_client().post(path).status_code, 302)
        self.kdelete.assert_not_called()

    def test_expiry_replay_and_source_lock(self):
        self.sync()
        operation = self.prepare()
        with self.b.app.app_context():
            op = self.b.db.session.get(self.b.RecordDeletion, operation)
            op.expires_at = 0
            source_id = op.source_id
            self.b.db.session.commit()
        self.assertEqual(self.execute(operation).status_code, 409)
        next_operation = self.prepare()
        self.assertNotEqual(operation, next_operation)
        with self.b.app.app_context():
            self.b.db.session.get(self.b.SourceRecord, source_id).busy = "dead-worker"
            self.b.db.session.commit()
        self.assertEqual(self.execute(next_operation).status_code, 409)
        self.kdelete.assert_not_called()

    def test_concurrent_confirmation_dispatches_kintone_delete_once(self):
        self.sync()
        operation = self.prepare()
        started, release = threading.Event(), threading.Event()
        original = self.kdelete.side_effect
        def slow(*args, **kwargs):
            started.set()
            if not release.wait(10):
                raise AssertionError("concurrency test timeout")
            return original(**kwargs)
        self.kdelete.side_effect = slow
        second = self.b.app.test_client()
        second.set_cookie(self.b.app.config["SESSION_COOKIE_NAME"], self.client.get_cookie(self.b.app.config["SESSION_COOKIE_NAME"]).value)
        responses = []
        thread = threading.Thread(target=lambda: responses.append(second.post("/records/123/delete",
            data={"csrf": "test-csrf", "operation_id": operation}).status_code))
        thread.start()
        try:
            self.assertTrue(started.wait(10))
            self.assertEqual(self.execute(operation).status_code, 409)
        finally:
            release.set()
            thread.join(10)
        self.assertFalse(thread.is_alive())
        self.assertEqual(responses, [200])
        self.assertEqual(self.kdelete.call_count, 1)

    def test_malformed_records_and_tables_fail_before_google_lookup(self):
        original = self.record()
        invalid = []
        for field in ("employee", "$id", "$revision", "schedule"):
            record = copy.deepcopy(original)
            record.pop(field)
            invalid.append(record)
        for field in self.b.controlled.ROW_FIELDS:
            record = copy.deepcopy(original)
            record["schedule"]["value"][0]["value"].pop(field)
            invalid.append(record)
        for table in (None, {}, "", [{"id": "456", "value": {}}]):
            record = copy.deepcopy(original)
            record["schedule"]["value"] = table
            invalid.append(record)
        for record in invalid:
            with self.subTest(record=record):
                self.records = {"123": record}
                with patch.object(self.b, "google_events") as lookup:
                    self.assertEqual(self.preview()[0].status_code, 502)
                    lookup.assert_not_called()

    def test_kintone_page_schema_and_monotonicity(self):
        for payload in ({}, {"records": None}, {"records": {}},
                        {"records": [{"$id": {"value": "2"}}, {"$id": {"value": "1"}}]},
                        {"records": [{"$id": {"value": "1"}}, {"$id": {"value": "1"}}]}):
            with self.subTest(payload=payload), patch.object(self.b.requests, "get", return_value=Mock(
                    status_code=200, headers={}, json=Mock(return_value=payload))), self.assertRaises(ValueError):
                self.b.kintone_records("offline", "employee in (LOGINUSER())")

    def test_second_page_failure_returns_no_partial_records(self):
        first = Mock(status_code=200, headers={}, json=Mock(return_value={"records": [
            {"$id": {"value": str(i)}} for i in range(1, 501)]}))
        with patch.object(self.b.requests, "get", side_effect=[first, requests.Timeout("page 2")]), self.assertRaises(requests.Timeout):
            self.b.kintone_records("offline", "employee in (LOGINUSER())")

    def test_google_page_token_cycle_and_invalid_items_fail(self):
        for response in ({"items": None}, {"items": [], "nextPageToken": "cycle"}):
            self.service.events.return_value.list.side_effect = None
            self.service.events.return_value.list.return_value.execute.return_value = response
            with self.assertRaises(ValueError):
                self.b.google_events(self.service, "test=value")

    def test_actual_exact_record_reader_rejects_permission_failure_and_incomplete_payload(self):
        from controlled_delete import ControlledDeletion
        row = Mock(user_code="employee-a")
        with patch.object(self.b.requests, "get", side_effect=requests.HTTPError("403")), self.assertRaises(requests.HTTPError):
            ControlledDeletion.exact_record(self.b.controlled, row, "123")
        for payload in ({}, {"record": self.record(record_id="999")}, {"record": {"$id": {"value": "123"}}}):
            with patch.object(self.b.requests, "get", return_value=Mock(status_code=200, headers={},
                    json=Mock(return_value=payload))), self.assertRaises(ValueError):
                ControlledDeletion.exact_record(self.b.controlled, row, "123")

    def test_identity_app_query_is_server_authenticated_and_unambiguous(self):
        from controlled_delete import ControlledDeletion
        valid = {"TestIdentityUser": {"value": [{"code": "employee-a"}]}}
        for result in ([], [valid, valid], [{"TestIdentityUser": {"value": []}}]):
            with patch.object(self.b, "kintone_records", return_value=result), self.assertRaises(ValueError):
                ControlledDeletion.identity(self.b.controlled, "employee-oauth")
        with patch.object(self.b, "kintone_records", return_value=[valid]) as query:
            self.assertEqual(ControlledDeletion.identity(self.b.controlled, "employee-oauth"), "employee-a")
        query.assert_called_once_with("employee-oauth", "TestIdentityUser in (LOGINUSER())", app_id=900001)

    def test_zero_record_identity_mismatch_and_unconfigured_identity_fail_closed(self):
        self.sync()
        operation = self.prepare()
        self.execute(operation)
        self.identity_patch.return_value = "employee-b"
        self.assertEqual(self.preview()[0].status_code, 502)
        self.identity_patch.return_value = "employee-a"
        self.b.app.config.update(KINTONE_IDENTITY_APP_ID="", KINTONE_IDENTITY_USER_FIELD="")
        self.assertEqual(self.preview()[0].status_code, 502)

    def test_quarantine_blocks_both_delete_endpoints(self):
        self.sync()
        operation = self.prepare()
        with self.b.app.app_context():
            self.b.db.session.add(self.b.GoogleQuarantine(user_code="employee-a", encrypted_snapshot=b"offline",
                backup_sha256="test", retired_at=time.time(), operator="test"))
            self.b.db.session.commit()
        for path in ("/records/123/delete/prepare", "/records/123/delete"):
            self.assertEqual(self.client.post(path, data={"csrf": "test-csrf", "operation_id": operation}).status_code, 400)
        self.kdelete.assert_not_called()

    def test_database_schema_creation_is_additive_and_idempotent(self):
        with self.b.app.app_context():
            original = self.b.db.session.get(self.b.Connection, "employee-a").kintone_tokens
            self.b.db.create_all()
            self.b.db.create_all()
            self.assertEqual(self.b.db.session.get(self.b.Connection, "employee-a").kintone_tokens, original)

    def test_fresh_login_with_zero_monthly_records_uses_identity_app(self):
        from controlled_delete import ControlledDeletion
        self.records = {}
        self.identity_patch.side_effect = lambda token: ControlledDeletion.identity(self.b.controlled, token)
        self.assertEqual(self.client.get("/login").status_code, 302)
        cookie = self.client.get_cookie(self.b.KINTONE_STATE_COOKIE, path="/kintone/callback").value
        state = self.b.kintone_state_signer.loads(cookie)
        token = Mock(json=Mock(return_value={"access_token": "offline", "refresh_token": "offline"}))
        with patch.object(self.b.requests, "post", return_value=token), patch.object(self.b, "kintone_records",
                return_value=[{"TestIdentityUser": {"value": [{"code": "employee-a"}]}}]) as query:
            response = self.client.get("/kintone/callback", query_string={"code": "offline", "state": state})
        self.assertEqual(response.status_code, 302)
        query.assert_called_once_with("offline", "TestIdentityUser in (LOGINUSER())", app_id=900001)
        with self.client.session_transaction() as session:
            self.assertEqual(session["user_code"], "employee-a")

    def test_unconfigured_identity_preserves_zero_record_login_rejection(self):
        from controlled_delete import ControlledDeletion
        self.b.app.config.update(KINTONE_IDENTITY_APP_ID="", KINTONE_IDENTITY_USER_FIELD="")
        self.identity_patch.side_effect = lambda token: ControlledDeletion.identity(self.b.controlled, token)
        self.client.get("/login")
        cookie = self.client.get_cookie(self.b.KINTONE_STATE_COOKIE, path="/kintone/callback").value
        state = self.b.kintone_state_signer.loads(cookie)
        with patch.object(self.b.requests, "post", return_value=Mock(json=Mock(return_value={"access_token": "offline"}))), \
                patch.object(self.b, "kintone_records", return_value=[]):
            self.assertEqual(self.client.get("/kintone/callback", query_string={"code": "offline", "state": state}).status_code, 403)

    def test_permission_loss_between_prepare_and_delete_never_dispatches(self):
        self.sync()
        operation = self.prepare()
        self.b.controlled.exact_record.side_effect = requests.HTTPError("permission denied")
        self.assertEqual(self.execute(operation).status_code, 502)
        self.kdelete.assert_not_called()
        with self.b.app.app_context():
            self.assertEqual(self.b.db.session.get(self.b.RecordDeletion, operation).state, "PREPARED")

    def test_google_etag_change_after_preview_blocks_delete(self):
        self.sync()
        operation = self.prepare()
        self.execute(operation)
        _, form = self.preview()
        next(iter(self.events.values()))["etag"] = '"changed"'
        self.assertEqual(self.client.post("/sync/apply", data=form).status_code, 409)
        self.assertEqual(len(self.events), 1)

    def test_reassignment_between_preview_and_apply_blocks_writes(self):
        self.sync()
        self.records["123"]["schedule"]["value"] = []
        _, form = self.preview()
        self.records["123"]["employee"]["value"] = [{"code": "employee-b"}]
        self.assertEqual(self.client.post("/sync/apply", data=form).status_code, 502)
        self.assertEqual(len(self.events), 1)

    def test_foreign_google_owner_after_preview_blocks_delete(self):
        self.sync()
        operation = self.prepare()
        self.execute(operation)
        _, form = self.preview()
        next(iter(self.events.values()))["extendedProperties"]["private"][self.b.SCOPE_TAG] = "employee-b"
        self.assertNotEqual(self.client.post("/sync/apply", data=form).status_code, 200)
        self.assertEqual(len(self.events), 1)

    def test_mapping_idempotency_and_cleanup_if_match(self):
        self.sync()
        self.sync()
        with self.b.app.app_context():
            self.assertEqual(self.b.SourceRecord.query.count(), 1)
            self.assertEqual(self.b.EventMapping.query.count(), 1)
            mapping = self.b.EventMapping.query.one()
            self.assertEqual((mapping.tenant, mapping.app_id, mapping.employee, mapping.record_id, mapping.row_id,
                mapping.google_sub, mapping.destination, mapping.revision),
                (self.b.KINTONE, 1675, "employee-a", "123", "456", "subject-a", "primary", "1"))
        operation = self.prepare()
        self.execute(operation)
        self.sync()
        self.assertEqual(len(self.delete_requests), 1)
        self.assertEqual(self.delete_requests[0].headers["If-Match"], '"v1"')

    def test_kintone_warning_blocks_incomplete_retrieval(self):
        with patch.object(self.b.requests, "get", return_value=Mock(status_code=200,
                headers={"X-Cybozu-Warning": "truncated"}, json=Mock(return_value={"records": []}))), self.assertRaises(ValueError):
            self.b.kintone_records("offline", "employee in (LOGINUSER())")

    def test_confirmed_tombstone_reappearing_record_blocks_sync(self):
        self.sync()
        operation = self.prepare()
        self.execute(operation)
        self.records["123"] = self.record()
        self.assertEqual(self.preview()[0].status_code, 502)
        self.assertEqual(len(self.events), 1)

    def test_expired_google_approval_never_cleans_up(self):
        self.sync()
        operation = self.prepare()
        self.execute(operation)
        _, form = self.preview()
        with self.b.app.app_context():
            approval = self.b.db.session.get(self.b.SyncApproval, self.b.digest(form["approval"]))
            approval.expires_at = 0
            self.b.db.session.commit()
        self.assertEqual(self.client.post("/sync/apply", data=form).status_code, 409)
        self.assertEqual(len(self.events), 1)

    def test_empty_final_month_can_be_genuinely_deleted(self):
        self.records["123"]["schedule"]["value"] = []
        operation = self.prepare()
        self.assertEqual(self.execute(operation).json["state"], "CONFIRMED")
        self.assertEqual(self.records, {})
        self.sync()
        self.assertEqual(self.mutations, [])

    def test_deleting_one_month_preserves_other_month_and_employee_events(self):
        self.records["999"] = self.record(record_id="999")
        self.sync()
        foreign = dict(copy.deepcopy(self.event()), id="foreign-event", etag='"foreign"')
        foreign["extendedProperties"]["private"][self.b.SCOPE_TAG] = "employee-b"
        foreign["extendedProperties"]["private"]["kintoneKey"] = "1675:777:456"
        self.events[foreign["id"]] = foreign
        operation = self.prepare()
        self.execute(operation)
        actions = self.plan()
        self.assertEqual([(a["key"], a["action"]) for a in actions],
                         [("1675:123:456", "DELETE"), ("1675:999:456", "UNCHANGED")])
        self.sync()
        self.assertEqual(len(self.events), 2)
        self.assertEqual(self.events[foreign["id"]], foreign)

    def test_conditional_delete_failure_does_not_mark_cleanup_done(self):
        self.sync()
        operation = self.prepare()
        self.execute(operation)
        self.delete_error = HttpError(Response({"status": "412"}), b'{}')
        _, form = self.preview()
        self.assertEqual(self.client.post("/sync/apply", data=form).status_code, 502)
        with self.b.app.app_context():
            self.assertEqual(self.b.EventCleanup.query.one().state, "UNKNOWN")
            self.assertEqual(self.b.EventMapping.query.one().state, "ACTIVE")
        self.assertEqual(len(self.events), 1)

    def test_google_foreign_tenant_blocks_prepare_and_cleanup(self):
        self.sync()
        event = next(iter(self.events.values()))
        event["extendedProperties"]["private"]["kintoneTenant"] = "https://foreign.example.invalid"
        self.assertEqual(self.client.post("/records/123/delete/prepare", data={"csrf": "test-csrf"}).status_code, 400)
        self.kdelete.assert_not_called()

    def test_delete_endpoint_credentials_are_not_returned(self):
        self.sync()
        response = self.client.post("/records/123/delete/prepare", data={"csrf": "test-csrf"})
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("offline-delete-token", response.get_data(as_text=True))
        self.assertNotIn("offline-kintone", response.get_data(as_text=True))
        self.assertEqual(response.json["events"][0]["key"], "1675:123:456")

    def test_uncertain_cleanup_invalidates_other_session_preview(self):
        self.sync()
        operation = self.prepare()
        self.execute(operation)
        first = self.client
        self.client = self.login_client("employee-a", "subject-a")
        _, second_form = self.preview()
        second = self.client
        self.client = first
        _, first_form = self.preview()
        self.delete_error = requests.Timeout("no response")
        self.assertEqual(first.post("/sync/apply", data=first_form).status_code, 502)
        self.delete_error = None
        self.assertEqual(second.post("/sync/apply", data=second_form).status_code, 409)
        self.assertEqual(len(self.events), 1)
        self.sync()
        self.assertEqual(self.events, {})

    def test_additive_upgrade_preserves_existing_connection_bytes(self):
        path = self.path.with_name("old-schema.db")
        with closing(sqlite3.connect(path)) as connection, connection:
            connection.execute("CREATE TABLE connection (user_code VARCHAR(150) PRIMARY KEY, "
                "kintone_tokens BLOB NOT NULL, google_tokens BLOB, updated_at FLOAT)")
            connection.execute("INSERT INTO connection VALUES (?, ?, ?, ?)",
                               ("preserved-user", b"old-kintone-bytes", b"old-google-bytes", 123.0))
        upgraded = timezone_tests.load_test_app("sqlite:///" + path.as_posix())
        try:
            with upgraded.app.app_context():
                upgraded.db.create_all()
                row = upgraded.db.session.get(upgraded.Connection, "preserved-user")
                self.assertEqual((row.kintone_tokens, row.google_tokens, row.updated_at),
                                 (b"old-kintone-bytes", b"old-google-bytes", 123.0))
                self.assertEqual(upgraded.RecordDeletion.query.count(), 0)
        finally:
            with upgraded.app.app_context():
                upgraded.db.session.remove()
                upgraded.db.engine.dispose()


if __name__ == "__main__":
    unittest.main()
