"""Offline security regressions using dummy grants and disposable SQLite files."""
import copy
import json
import re
import secrets
import sqlite3
import tempfile
import threading
import time
import unittest
from contextlib import closing
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from httplib2 import Response
from werkzeug.exceptions import HTTPException

import test_timezones as tz_tests


class SecurityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "offline.db"
        self.b = tz_tests.load_test_app("sqlite:///" + self.path.as_posix())
        self.addCleanup(self.dispose)
        self.network = patch("requests.sessions.Session.request",
                             side_effect=AssertionError("Live network forbidden"))
        self.network.start()
        self.addCleanup(self.network.stop)
        self.calendar_network = patch("httplib2.Http.request", side_effect=AssertionError("Live network forbidden"))
        self.calendar_network.start()
        self.addCleanup(self.calendar_network.stop)
        self.client = self.login_client("employee-a", "subject-a")

    def dispose(self):
        with self.b.app.app_context():
            self.b.db.session.remove()
            self.b.db.engine.dispose()

    def login_client(self, user, subject):
        b = self.b
        client = b.app.test_client()
        sid = secrets.token_urlsafe(32)
        with b.app.app_context():
            row = b.db.session.get(b.Connection, user)
            if row is None:
                b.db.session.add(b.Connection(user_code=user,
                    kintone_tokens=b.encrypt({"offline": "kintone"}),
                    google_tokens=b.encrypt({"token": "old-access", "refresh_token": "old-refresh"})))
                b.db.session.add(b.ConnectionSecurity(user_code=user, google_sub=subject,
                    google_label="Verified test account", version="version-1"))
            b.db.session.add(b.BrowserSession(sid_hash=b.digest(sid), user_code=user,
                                            expires_at=time.time() + 3600))
            b.db.session.commit()
        with client.session_transaction() as session:
            session.update(sid=sid, user_code=user, csrf="test-csrf")
        return client

    def event(self):
        sample = tz_tests.TimezoneTests()
        return self.b.row_event({"$id": {"value": "123"}}, sample.row(), "employee-a")

    def actions(self):
        return [{"action": "CREATE", "key": "1675:123:456", "title": "Test visit",
                 "eventId": None, "body": self.event()}]

    def preview(self, actions=None):
        actions = self.actions() if actions is None else actions
        service = Mock()
        with patch.object(self.b, "google_service", return_value=service), \
                patch.object(self.b, "build_plan", return_value=(actions, "fingerprint-1", 1)):
            response = self.client.get("/sync/preview")
        self.assertEqual(response.status_code, 200)
        text = response.get_data(as_text=True)
        token = re.search(r'name="approval" value="([^"]+)"', text)
        return ({"approval": token.group(1), "fingerprint": "fingerprint-1", "csrf": "test-csrf"}
                if token else None), service

    def authorize_state(self, client=None):
        client = client or self.client
        flow = Mock(code_verifier="offline-verifier")
        flow.authorization_url.side_effect = lambda **kw: ("https://example.invalid/auth", kw["state"])
        with patch.object(self.b, "google_flow", return_value=flow):
            response = client.get("/google/connect")
        self.assertEqual(response.status_code, 302)
        signed = client.get_cookie(self.b.GOOGLE_STATE_COOKIE, path="/google/callback").value
        return self.b.google_state_signer.loads(signed), flow

    def token_fixture(self, refresh="new-refresh", subject="subject-a"):
        credentials = Mock(id_token="signed-offline-id-token", granted_scopes=self.b.GOOGLE_SCOPE)
        credentials.to_json.return_value = json.dumps({"token": "new-access", "refresh_token": refresh,
                                                       "scopes": self.b.GOOGLE_SCOPE})
        refreshed = Mock(granted_scopes=self.b.GOOGLE_SCOPE)
        refreshed.to_json.return_value = json.dumps({"token": "refreshed-access", "refresh_token": refresh})
        claims = {"sub": subject, "nonce": "nonce", "aud": "test-client"}
        profile = {"sub": subject, "email": "test@example.invalid", "email_verified": True}
        return credentials, refreshed, claims, profile

    def verify_tokens(self, credentials, refreshed, claims, profiles, previous=None, allow_legacy_migration=False):
        b = self.b
        with b.app.app_context(), patch.object(b, "google_client", return_value={"client_id": "test-client"}), \
                patch.object(b.id_token, "verify_oauth2_token", return_value=claims) as verifier, \
                patch.object(b, "access_identity", side_effect=profiles), \
                patch.object(b, "google_credentials", return_value=refreshed):
            result = b.verified_google_tokens(credentials, "nonce", previous or {},
                                             b.security_for("employee-a"),
                                             allow_legacy_migration=allow_legacy_migration)
            verifier.assert_called_once()
            self.assertEqual(verifier.call_args.args[2], "test-client")
            return result

    def test_verified_same_account_reuses_only_verified_refresh(self):
        credentials, refreshed, claims, profile = self.token_fixture(refresh=None)
        refreshed.to_json.return_value = json.dumps({"token": "safe", "refresh_token": "old-refresh"})
        tokens, subject, _ = self.verify_tokens(credentials, refreshed, claims, [profile, profile],
                                               {"refresh_token": "old-refresh"})
        self.assertEqual(tokens["refresh_token"], "old-refresh")
        self.assertEqual(subject, "subject-a")
        refreshed.refresh.assert_called_once()

    def test_account_switch_is_rejected(self):
        credentials, refreshed, claims, profile = self.token_fixture(subject="subject-b")
        with self.assertRaisesRegex(ValueError, "switching is blocked"):
            self.verify_tokens(credentials, refreshed, claims, [profile])
        refreshed.refresh.assert_not_called()

    def test_refresh_subject_mismatch_is_rejected(self):
        credentials, refreshed, claims, profile = self.token_fixture()
        with self.assertRaisesRegex(ValueError, "Refresh token ownership"):
            self.verify_tokens(credentials, refreshed, claims, [profile, {"sub": "subject-b"}])

    def test_id_token_nonce_and_access_subject_are_verified(self):
        for bad_claims in ({"nonce": "wrong", "sub": "subject-a"},
                           {"nonce": "nonce", "sub": "other"},
                           {"nonce": "nonce", "sub": "subject-a", "azp": "other-client"}):
            credentials, refreshed, _, profile = self.token_fixture()
            with self.subTest(claims=bad_claims), self.assertRaisesRegex(ValueError, "identity verification"):
                self.verify_tokens(credentials, refreshed, bad_claims, [profile])

    def test_failed_signature_verification_preserves_connection(self):
        b = self.b
        oauth, flow = self.authorize_state()
        credentials, _, _, _ = self.token_fixture()
        flow.credentials = credentials
        with b.app.app_context():
            before = b.db.session.get(b.Connection, "employee-a").google_tokens
        with patch.object(b, "google_flow", return_value=flow), \
                patch.object(b, "google_client", return_value={"client_id": "test-client"}), \
                patch.object(b.id_token, "verify_oauth2_token", side_effect=ValueError("bad signature")):
            response = self.client.get("/google/callback", query_string={"state": oauth["state"], "code": "dummy"})
        self.assertEqual(response.status_code, 400)
        with b.app.app_context():
            self.assertEqual(before, b.db.session.get(b.Connection, "employee-a").google_tokens)
            self.assertEqual(b.security_for("employee-a").google_sub, "subject-a")

    def test_one_google_subject_cannot_bind_two_employees(self):
        self.login_client("employee-b", "subject-b")
        credentials, refreshed, claims, profile = self.token_fixture(subject="subject-b")
        with self.b.app.app_context():
            self.b.security_for("employee-a").google_sub = None
            self.b.db.session.commit()
        with self.assertRaisesRegex(ValueError, "another employee"):
            self.verify_tokens(credentials, refreshed, claims, [profile])

    def test_first_authorization_requires_refresh_token(self):
        with self.b.app.app_context():
            self.b.security_for("employee-a").google_sub = None
            self.b.db.session.commit()
        credentials, refreshed, claims, profile = self.token_fixture(refresh=None)
        with self.assertRaisesRegex(ValueError, "safe refresh token"):
            self.verify_tokens(credentials, refreshed, claims, [profile])

    def test_other_legacy_connection_must_be_verified_before_new_binding(self):
        self.login_client("employee-b", None)
        credentials, refreshed, claims, profile = self.token_fixture()
        with self.assertRaisesRegex(ValueError, "Verify it first"):
            self.verify_tokens(credentials, refreshed, claims, [profile])

    def make_a_legacy(self):
        with self.b.app.app_context():
            security = self.b.security_for("employee-a")
            security.google_sub = None
            security.google_label = None
            self.b.db.session.commit()

    def quarantine_a(self, backup_name="quarantine.fernet"):
        path = Path(self.temp.name) / backup_name
        with self.b.app.app_context():
            self.b.quarantine_legacy_google("employee-a", "employee-a", path, "offline-admin")
        return path

    def test_quarantine_archives_ciphertext_and_changes_only_selected_employee(self):
        b = self.b
        self.make_a_legacy()
        other = self.login_client("employee-b", "subject-b")
        with b.app.app_context():
            a = b.db.session.get(b.Connection, "employee-a")
            original = (a.kintone_tokens, a.google_tokens, a.updated_at)
            b_row = b.db.session.get(b.Connection, "employee-b")
            untouched = (b_row.kintone_tokens, b_row.google_tokens, b.security_for("employee-b").version)
            old_version = b.security_for("employee-a").version
            for user in ("employee-a", "employee-b"):
                browser = b.BrowserSession.query.filter_by(user_code=user).first()
                browser.google_state = "pending"
                b.db.session.add(b.SyncApproval(token_hash=user, sid_hash=browser.sid_hash,
                    user_code=user, google_sub="dummy", destination="primary", version="old",
                    fingerprint="old", expires_at=time.time() + 300))
            b.db.session.commit()
        path = self.quarantine_a()
        with b.app.app_context():
            archive = b.db.session.get(b.GoogleQuarantine, "employee-a")
            saved = path.read_bytes()
            self.assertEqual(saved, archive.encrypted_snapshot)
            self.assertEqual(b.hashlib.sha256(saved).hexdigest(), archive.backup_sha256)
            snapshot = b.decrypt(saved)
            self.assertEqual(snapshot["connection"]["google_tokens"].encode("ascii"), original[1])
            self.assertEqual(snapshot["connection"]["kintone_tokens"].encode("ascii"), original[0])
            self.assertEqual(snapshot["security"]["version"], old_version)
            a = b.db.session.get(b.Connection, "employee-a")
            self.assertEqual((a.kintone_tokens, a.updated_at), (original[0], original[2]))
            self.assertIsNone(a.google_tokens)
            self.assertIsNone(b.security_for("employee-a").google_sub)
            self.assertNotEqual(b.security_for("employee-a").version, old_version)
            self.assertIsNone(b.security_for("employee-a").busy)
            self.assertEqual(b.SyncApproval.query.filter_by(user_code="employee-a").count(), 0)
            self.assertEqual(b.BrowserSession.query.filter_by(user_code="employee-a").count(), 0)
            b_row = b.db.session.get(b.Connection, "employee-b")
            self.assertEqual((b_row.kintone_tokens, b_row.google_tokens,
                              b.security_for("employee-b").version), untouched)
            self.assertEqual(b.SyncApproval.query.filter_by(user_code="employee-b").count(), 1)
            self.assertEqual(b.BrowserSession.query.filter_by(user_code="employee-b").first().google_state, "pending")
        self.assertEqual(other.get("/").status_code, 200)

    def test_new_employee_b_verified_callback_succeeds_only_after_quarantine(self):
        b = self.b
        self.make_a_legacy()
        other = self.login_client("employee-b", None)
        with b.app.app_context():
            b.db.session.get(b.Connection, "employee-b").google_tokens = None
            b.db.session.commit()
        for quarantined in (False, True):
            if quarantined:
                self.quarantine_a()
            oauth, flow = self.authorize_state(other)
            credentials, refreshed, claims, profile = self.token_fixture(subject="subject-b")
            claims["nonce"] = oauth["nonce"]
            flow.credentials = credentials
            with patch.object(b, "google_flow", return_value=flow), \
                    patch.object(b, "google_client", return_value={"client_id": "test-client"}), \
                    patch.object(b.id_token, "verify_oauth2_token", return_value=claims), \
                    patch.object(b, "access_identity", side_effect=[profile, profile]), \
                    patch.object(b, "google_credentials", return_value=refreshed), \
                    patch.object(b, "build") as calendar:
                response = other.get("/google/callback", query_string={"state": oauth["state"], "code": "dummy"})
            self.assertEqual(response.status_code, 302 if quarantined else 400)
            calendar.assert_not_called()
            with b.app.app_context():
                row = b.db.session.get(b.Connection, "employee-b")
                if quarantined:
                    self.assertEqual(b.security_for("employee-b").google_sub, "subject-b")
                    self.assertEqual(b.decrypt(row.google_tokens)["token"], "refreshed-access")
                else:
                    self.assertIsNone(row.google_tokens)

    def test_quarantined_employee_cannot_reconnect_or_sync_even_after_new_kintone_session(self):
        b = self.b
        self.make_a_legacy()
        self.quarantine_a()
        self.assertEqual(self.client.get("/sync/preview").status_code, 302)
        new_session = self.login_client("employee-a", None)
        with patch.object(b, "google_flow") as oauth, patch.object(b, "google_service") as service, \
                patch.object(b, "get_self_records") as records:
            for route, method in (("/google/connect", "get"), ("/google/callback", "get"),
                                  ("/sync/preview", "get"), ("/sync/apply", "post"),
                                  ("/google/disconnect", "post")):
                response = getattr(new_session, method)(route)
                self.assertEqual(response.status_code, 400)
                self.assertIn("quarantined", response.get_data(as_text=True))
            oauth.assert_not_called()
            service.assert_not_called()
            records.assert_not_called()
        dashboard = new_session.get("/").get_data(as_text=True)
        self.assertIn("Quarantined", dashboard)
        self.assertNotIn('href="/google/connect"', dashboard)
        self.assertNotIn('href="/sync/preview"', dashboard)
        self.assertEqual(new_session.post("/logout", data={"csrf": "test-csrf"}).status_code, 200)

    def test_quarantine_does_not_adopt_update_or_delete_four_owned_a_events(self):
        b = self.b
        self.make_a_legacy()
        self.quarantine_a()
        events = []
        for number in range(4):
            event = copy.deepcopy(self.event())
            event["id"] = "original-google-event-" + str(number)
            event["extendedProperties"]["private"]["kintoneKey"] = f"1675:123:{number}"
            events.append(event)
        before = copy.deepcopy(events)
        row = tz_tests.TimezoneTests().row()
        record = {"$id": {"value": "123"}, "schedule": {"value": [row]}}
        with b.app.app_context(), patch.object(b, "get_self_records", return_value=[record]), \
                patch.object(b, "google_events", side_effect=[events, []]):
            actions, _, _ = b.build_plan(SimpleNamespace(user_code="employee-b"), Mock())
        self.assertEqual([a["action"] for a in actions], ["CREATE"])
        self.assertEqual(events, before)
        self.assertTrue(all(a["eventId"] not in [e["id"] for e in events] for a in actions))

    def test_quarantine_blocks_unowned_legacy_adoption_and_existing_other_owner_checks_remain(self):
        b = self.b
        self.make_a_legacy()
        self.quarantine_a()
        event = dict(self.event(), id="original-google-id")
        record = {"$id": {"value": "123"}, "schedule": {"value": [tz_tests.TimezoneTests().row()]}}
        for owner in (None, "employee-a"):
            if owner is None:
                event["extendedProperties"]["private"].pop(b.SCOPE_TAG, None)
            else:
                event["extendedProperties"]["private"][b.SCOPE_TAG] = owner
            before = copy.deepcopy(event)
            with b.app.app_context(), patch.object(b, "get_self_records", return_value=[record]), \
                    patch.object(b, "google_events", side_effect=[[], [event]]), self.assertRaises(ValueError):
                b.build_plan(SimpleNamespace(user_code="employee-b"), Mock())
            self.assertEqual(event, before)

    def test_quarantine_does_not_weaken_verified_cross_employee_subject_check(self):
        b = self.b
        self.make_a_legacy()
        self.quarantine_a()
        self.login_client("employee-b", "subject-b")
        self.login_client("employee-c", None)
        credentials, refreshed, claims, profile = self.token_fixture(subject="subject-b")
        with b.app.app_context(), patch.object(b, "google_client", return_value={"client_id": "test-client"}), \
                patch.object(b.id_token, "verify_oauth2_token", return_value=claims), \
                patch.object(b, "access_identity", return_value=profile), \
                patch.object(b, "google_credentials", return_value=refreshed):
            with self.assertRaisesRegex(ValueError, "another employee"):
                b.verified_google_tokens(credentials, "nonce", {}, b.security_for("employee-c"))
        refreshed.refresh.assert_not_called()

    def test_quarantine_requires_backup_and_never_overwrites_existing_file(self):
        b = self.b
        self.make_a_legacy()
        with b.app.app_context():
            original = b.db.session.get(b.Connection, "employee-a").google_tokens
            version = b.security_for("employee-a").version
        existing = Path(self.temp.name) / "already-exists.fernet"
        existing.write_bytes(b"keep-this-file")
        for backup in (existing, Path(self.temp.name) / "missing-directory" / "backup"):
            with b.app.app_context(), self.assertRaisesRegex(ValueError, "not retired"):
                b.quarantine_legacy_google("employee-a", "employee-a", backup, "offline-admin")
            with b.app.app_context():
                self.assertEqual(b.db.session.get(b.Connection, "employee-a").google_tokens, original)
                self.assertEqual(b.security_for("employee-a").version, version)
                self.assertIsNone(b.security_for("employee-a").busy)
                self.assertEqual(b.GoogleQuarantine.query.count(), 0)
        self.assertEqual(existing.read_bytes(), b"keep-this-file")

    def test_quarantine_refuses_wrong_confirmation_unknown_or_verified_target(self):
        b = self.b
        path = Path(self.temp.name) / "not-created.fernet"
        for user, confirmation in (("employee-a", "employee-b"), ("missing", "missing"),
                                   ("employee-a", "employee-a")):
            with b.app.app_context(), self.assertRaises(ValueError):
                b.quarantine_legacy_google(user, confirmation, path, "offline-admin")
        self.assertFalse(path.exists())

    def test_quarantine_commit_failure_preserves_active_tokens_and_retains_backup(self):
        b = self.b
        self.make_a_legacy()
        path = Path(self.temp.name) / "retained-after-failure.fernet"
        with b.app.app_context():
            original = b.db.session.get(b.Connection, "employee-a").google_tokens
            version = b.security_for("employee-a").version
            commit = b.db.session.commit
            commits = []
            def fail_retirement_commit():
                commits.append(True)
                if len(commits) == 2:
                    raise b.SQLAlchemyError("offline transaction failure")
                return commit()
            with patch.object(b.db.session, "commit", side_effect=fail_retirement_commit), \
                    self.assertRaises(b.SQLAlchemyError):
                b.quarantine_legacy_google("employee-a", "employee-a", path, "offline-admin")
            self.assertEqual(b.db.session.get(b.Connection, "employee-a").google_tokens, original)
            self.assertEqual(b.security_for("employee-a").version, version)
            self.assertIsNone(b.security_for("employee-a").busy)
            self.assertEqual(b.GoogleQuarantine.query.count(), 0)
            self.assertEqual(b.decrypt(path.read_bytes())["connection"]["google_tokens"].encode("ascii"), original)

    def test_quarantine_is_one_time_and_busy_connection_is_not_retired(self):
        b = self.b
        self.make_a_legacy()
        with b.app.app_context():
            b.security_for("employee-a").busy = "running-sync"
            b.db.session.commit()
        with self.assertRaises(HTTPException) as error:
            self.quarantine_a()
        self.assertEqual(error.exception.code, 409)
        with b.app.app_context():
            self.assertIsNotNone(b.db.session.get(b.Connection, "employee-a").google_tokens)
            b.security_for("employee-a").busy = None
            b.db.session.commit()
        path = self.quarantine_a()
        original = path.read_bytes()
        with self.assertRaisesRegex(ValueError, "quarantined"):
            self.quarantine_a("second-backup.fernet")
        self.assertEqual(path.read_bytes(), original)
        self.assertFalse((Path(self.temp.name) / "second-backup.fernet").exists())

    def test_quarantine_cli_is_local_only_and_requires_explicit_target_confirmation(self):
        b = self.b
        self.make_a_legacy()
        runner = b.app.test_cli_runner()
        path = Path(self.temp.name) / "cli-backup.fernet"
        self.assertNotEqual(runner.invoke(args=["quarantine-legacy-google"]).exit_code, 0)
        self.assertFalse(path.exists())
        result = runner.invoke(args=["quarantine-legacy-google", "--employee-code", "employee-a",
            "--confirm-employee-code", "employee-a", "--operator", "offline-admin", "--backup", str(path)])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("quarantined", result.output)
        self.assertNotIn("old-refresh", result.output)
        self.assertTrue(path.exists())
        self.assertEqual(self.client.post("/quarantine-legacy-google").status_code, 404)

    def test_legacy_disconnect_keeps_subject_binding_and_tokens_on_failure(self):
        b = self.b
        with b.app.app_context():
            b.security_for("employee-a").google_sub = None
            before = b.db.session.get(b.Connection, "employee-a").google_tokens
            b.db.session.commit()
        with patch.object(b, "legacy_subject", side_effect=ValueError("Cannot verify legacy")), \
                patch.object(b.requests, "post") as revoke:
            self.assertEqual(self.client.post("/google/disconnect", data={"csrf": "test-csrf"}).status_code, 400)
            revoke.assert_not_called()
        with b.app.app_context():
            self.assertEqual(before, b.db.session.get(b.Connection, "employee-a").google_tokens)
        with patch.object(b, "legacy_subject", return_value="subject-a"), \
                patch.object(b.requests, "post", return_value=Mock(status_code=200)):
            self.assertEqual(self.client.post("/google/disconnect", data={"csrf": "test-csrf"}).status_code, 302)
        with b.app.app_context():
            self.assertEqual(b.security_for("employee-a").google_sub, "subject-a")
            self.assertIsNone(b.db.session.get(b.Connection, "employee-a").google_tokens)

    def test_successful_callback_saves_verified_tokens_and_invalidates_preview(self):
        b = self.b
        oauth, flow = self.authorize_state()
        form, _ = self.preview()
        credentials, refreshed, claims, profile = self.token_fixture()
        claims["nonce"] = oauth["nonce"]
        flow.credentials = credentials
        with b.app.app_context():
            before_version = b.security_for("employee-a").version
        with patch.object(b, "google_flow", return_value=flow), \
                patch.object(b, "google_client", return_value={"client_id": "test-client"}), \
                patch.object(b.id_token, "verify_oauth2_token", return_value=claims), \
                patch.object(b, "access_identity", side_effect=[profile, profile]), \
                patch.object(b, "google_credentials", return_value=refreshed):
            response = self.client.get("/google/callback", query_string={"state": oauth["state"], "code": "dummy"})
        self.assertEqual(response.status_code, 302)
        with b.app.app_context():
            row = b.db.session.get(b.Connection, "employee-a")
            self.assertEqual(b.decrypt(row.google_tokens)["token"], "refreshed-access")
            self.assertEqual(b.security_for("employee-a").google_sub, "subject-a")
            self.assertNotEqual(b.security_for("employee-a").version, before_version)
        self.assertEqual(self.client.post("/sync/apply", data=form).status_code, 409)
        flow.fetch_token.assert_called_once()
        self.assertTrue(flow.fetch_token.call_args.kwargs["authorization_response"].startswith(
            "https://calendar.example.invalid/google/callback?"))

    def test_runtime_token_refresh_cannot_change_account_or_overwrite_on_failure(self):
        b = self.b
        for valid in (False, True):
            credentials = Mock(valid=valid)
            with b.app.app_context():
                row = b.db.session.get(b.Connection, "employee-a")
                before = row.google_tokens
                with patch.object(b, "google_credentials", return_value=credentials), \
                        patch.object(b, "access_identity", return_value={"sub": "subject-b"}), \
                        patch.object(b, "build") as calendar:
                    with self.assertRaisesRegex(ValueError, "mismatch"):
                        b.google_service(row)
                    self.assertEqual(row.google_tokens, before)
                    calendar.assert_not_called()

    def test_legacy_introspection_requires_subject_audience_and_lifetime(self):
        b = self.b
        credentials = Mock(token="offline-access")
        with patch.object(b, "google_credentials", return_value=credentials), \
                patch.object(b, "google_client", return_value={"client_id": "test-client"}), \
                patch.object(b.requests, "get") as introspect:
            introspect.return_value.status_code = 200
            for info in ({"sub": "subject-a", "aud": "wrong", "expires_in": 100},
                         {"aud": "test-client", "expires_in": 100},
                         {"sub": "subject-a", "aud": "test-client", "expires_in": 0}):
                introspect.return_value.json.return_value = info
                with self.assertRaisesRegex(ValueError, "Legacy Google account could not be verified"):
                    b.legacy_subject({"refresh_token": "offline-refresh"})
            introspect.return_value.json.return_value = {"sub": "subject-a", "aud": "test-client", "expires_in": 100}
            self.assertEqual(b.legacy_subject({"refresh_token": "offline-refresh"}), "subject-a")

    def test_missing_calendar_permission_rejects_connection(self):
        credentials, refreshed, claims, profile = self.token_fixture()
        credentials.granted_scopes = ["openid"]
        with self.assertRaisesRegex(ValueError, "identity verification"):
            self.verify_tokens(credentials, refreshed, claims, [profile])

    def test_legacy_upgrade_fails_closed_or_matches_old_subject(self):
        with self.b.app.app_context():
            self.b.security_for("employee-a").google_sub = None
            self.b.db.session.commit()
        credentials, refreshed, claims, profile = self.token_fixture()
        with patch.object(self.b, "legacy_subject", return_value="subject-b"), \
                self.assertRaisesRegex(ValueError, "switching is blocked"):
            self.verify_tokens(credentials, refreshed, claims, [profile], {"refresh_token": "legacy"}, True)
        with patch.object(self.b, "legacy_subject", return_value="subject-a"):
            _, subject, _ = self.verify_tokens(credentials, refreshed, claims, [profile, profile],
                                               {"refresh_token": "legacy"}, True)
        self.assertEqual(subject, "subject-a")

    def legacy_lookup_fixture(self, valid=True):
        credentials = Mock(valid=valid, token="offline-old-access")
        client = patch.object(self.b, "google_client", return_value={"client_id": "test-client"})
        factory = patch.object(self.b, "google_credentials", return_value=credentials)
        client.start()
        factory.start()
        self.addCleanup(client.stop)
        self.addCleanup(factory.stop)
        return credentials

    def test_legacy_expired_access_token_refreshes_only_old_credentials(self):
        credentials = self.legacy_lookup_fixture(valid=False)
        previous = {"token": "expired", "refresh_token": "old-only", "scopes": [self.b.GOOGLE_SCOPE[0]]}
        before = copy.deepcopy(previous)
        info = {"sub": "subject-a", "aud": "test-client", "expires_in": 100,
                "scope": self.b.GOOGLE_SCOPE[0]}
        with patch.object(self.b.requests, "get", return_value=Mock(status_code=200, json=lambda: info)):
            self.assertEqual(self.b.legacy_subject(previous), "subject-a")
        credentials.refresh.assert_called_once()
        self.assertEqual(previous, before)

    def test_legacy_valid_access_token_does_not_require_refresh(self):
        credentials = self.legacy_lookup_fixture()
        info = {"sub": "subject-a", "aud": "test-client", "expires_in": 100}
        with patch.object(self.b.requests, "get", return_value=Mock(status_code=200, json=lambda: info)):
            self.assertEqual(self.b.legacy_subject({}), "subject-a")
        credentials.refresh.assert_not_called()

    def test_legacy_revoked_refresh_reports_safe_stage(self):
        credentials = self.legacy_lookup_fixture(valid=False)
        credentials.refresh.side_effect = self.b.RefreshError("sensitive-provider-response")
        with self.assertRaises(self.b.LegacyVerificationError) as error:
            self.b.legacy_subject({})
        self.assertEqual(error.exception.code, "legacy.refresh_rejected")
        self.assertNotIn("sensitive-provider-response", str(error.exception))

    def test_legacy_refresh_scope_and_client_failures_are_distinguished(self):
        credentials = self.legacy_lookup_fixture(valid=False)
        for category, code in (("invalid_scope", "legacy.refresh_scope_rejected"),
                               ("invalid_client", "legacy.oauth_client_rejected"),
                               ("invalid_grant", "legacy.refresh_rejected")):
            credentials.refresh.side_effect = self.b.RefreshError(
                "private-description", {"error": category, "error_description": "private-description"}
            )
            with self.subTest(category=category), self.assertRaises(self.b.LegacyVerificationError) as error:
                self.b.legacy_subject({})
            self.assertEqual(error.exception.code, code)
            self.assertNotIn("private-description", str(error.exception))

    def test_legacy_missing_subject_and_missing_scopes_remain_blocked(self):
        self.legacy_lookup_fixture()
        cases = (
            ({"aud": "test-client", "expires_in": 100, "scope": self.b.GOOGLE_SCOPE[0]}, "legacy.subject_missing"),
            ({"sub": "subject-a", "aud": "test-client", "expires_in": 100, "scope": "openid"},
             "legacy.calendar_scope_missing"),
            ({"sub": "subject-a", "aud": "test-client", "expires_in": 0}, "legacy.token_expired"),
            ({"sub": "subject-a", "aud": "test-client", "audience": "other", "expires_in": 100},
             "legacy.client_mismatch"),
        )
        for info, code in cases:
            with self.subTest(code=code), patch.object(
                self.b.requests, "get", return_value=Mock(status_code=200, json=lambda: info)
            ), self.assertRaises(self.b.LegacyVerificationError) as error:
                self.b.legacy_subject({})
            self.assertEqual(error.exception.code, code)

    def test_legacy_lookup_failures_never_expose_request_or_response(self):
        credentials = self.legacy_lookup_fixture()
        for response, code in ((Mock(status_code=403), "legacy.lookup_rejected"),
                               (Mock(status_code=200, json=Mock(side_effect=ValueError("private-json"))),
                                "legacy.response_invalid")):
            with self.subTest(code=code), patch.object(self.b.requests, "get", return_value=response), \
                    self.assertRaises(self.b.LegacyVerificationError) as error:
                self.b.legacy_subject({})
            self.assertEqual(error.exception.code, code)
            self.assertNotIn("private-json", str(error.exception))
        with patch.object(self.b.requests, "get", side_effect=self.b.requests.RequestException("token=do-not-expose")), \
                self.assertRaises(self.b.LegacyVerificationError) as error:
            self.b.legacy_subject({})
        self.assertEqual(error.exception.code, "legacy.lookup_unavailable")
        self.assertNotIn("do-not-expose", str(error.exception))
        credentials.refresh.assert_not_called()

    def test_legacy_v2_identifier_bridge_matches_independently_verified_new_account(self):
        credentials = self.legacy_lookup_fixture()
        modern = {"aud": "test-client", "expires_in": 100, "scope": self.b.GOOGLE_SCOPE[0]}
        # Neither email nor equivalence between user_id and sub is assumed.
        legacy = {"audience": "test-client", "issued_to": "test-client", "expires_in": 100,
                  "user_id": "older-api-identifier", "email": "same@example.invalid"}
        reference = Mock(token="offline-new-access")
        with patch.object(self.b.requests, "get", return_value=Mock(status_code=200, json=lambda: modern)), \
                patch.object(self.b.requests, "post", side_effect=[
                    Mock(status_code=200, json=lambda: legacy), Mock(status_code=200, json=lambda: legacy)
                ]) as lookup:
            self.assertEqual(self.b.legacy_subject({}, reference, "verified-oidc-sub"), "verified-oidc-sub")
        self.assertEqual([c.kwargs["params"]["access_token"] for c in lookup.call_args_list],
                         [credentials.token, reference.token])
        self.assertTrue(all(c.kwargs["allow_redirects"] is False for c in lookup.call_args_list))

    def test_legacy_v2_mismatch_rejected_even_with_same_email(self):
        self.legacy_lookup_fixture()
        modern = {"aud": "test-client", "expires_in": 100}
        old = {"audience": "test-client", "expires_in": 100, "user_id": "one", "email": "same@example.invalid"}
        new = dict(old, user_id="two")
        with patch.object(self.b.requests, "get", return_value=Mock(status_code=200, json=lambda: modern)), \
                patch.object(self.b.requests, "post", side_effect=[
                    Mock(status_code=200, json=lambda: old), Mock(status_code=200, json=lambda: new)
                ]), self.assertRaises(self.b.LegacyVerificationError) as error:
            self.b.legacy_subject({}, Mock(token="new"), "verified-sub")
        self.assertEqual(error.exception.code, "legacy.account_mismatch")

    def test_legacy_v2_missing_identity_cannot_be_replaced_by_email(self):
        self.legacy_lookup_fixture()
        info = {"aud": "test-client", "audience": "test-client", "expires_in": 100,
                "email": "same@example.invalid", "verified_email": True}
        with patch.object(self.b.requests, "get", return_value=Mock(status_code=200, json=lambda: info)), \
                patch.object(self.b.requests, "post", return_value=Mock(status_code=200, json=lambda: info)), \
                self.assertRaises(self.b.LegacyVerificationError) as error:
            self.b.legacy_subject({}, Mock(token="new"), "verified-sub")
        self.assertEqual(error.exception.code, "legacy.subject_missing")

    def test_legacy_migration_requires_csrf_and_explicit_consent(self):
        b = self.b
        with b.app.app_context():
            b.security_for("employee-a").google_sub = None
            b.db.session.commit()
        with patch.object(b, "google_flow") as flow:
            response = self.client.get("/google/connect")
            self.assertEqual(response.status_code, 200)
            self.assertIn("Verify and migrate the same Google account", response.get_data(as_text=True))
            self.assertEqual(self.client.post("/google/connect", data={"legacy_migration": "verify_same_account"}).status_code, 403)
            self.assertEqual(self.client.post("/google/connect", data={"csrf": "test-csrf"}).status_code, 400)
            flow.assert_not_called()
        credentials, refreshed, claims, profile = self.token_fixture()
        with self.assertRaisesRegex(ValueError, "Explicit legacy migration consent"):
            self.verify_tokens(credentials, refreshed, claims, [profile], {"refresh_token": "legacy"})

    def test_explicit_legacy_callback_preserves_original_blob_and_rejects_mismatch(self):
        b = self.b
        with b.app.app_context():
            b.security_for("employee-a").google_sub = None
            original = b.db.session.get(b.Connection, "employee-a").google_tokens
            b.db.session.commit()
        for old_subject in ("different-subject", "subject-a"):
            flow = Mock(code_verifier="offline")
            flow.authorization_url.side_effect = lambda **kw: ("https://example.invalid/auth", kw["state"])
            with patch.object(b, "google_flow", return_value=flow):
                response = self.client.post("/google/connect", data={
                    "csrf": "test-csrf", "legacy_migration": "verify_same_account"
                })
            self.assertEqual(response.status_code, 302)
            signed = self.client.get_cookie(b.GOOGLE_STATE_COOKIE, path="/google/callback").value
            oauth = b.google_state_signer.loads(signed)
            self.assertIs(oauth["legacy_migration"], True)
            credentials, refreshed, claims, profile = self.token_fixture()
            claims["nonce"] = oauth["nonce"]
            flow.credentials = credentials
            with patch.object(b, "google_flow", return_value=flow), \
                    patch.object(b, "google_client", return_value={"client_id": "test-client"}), \
                    patch.object(b.id_token, "verify_oauth2_token", return_value=claims), \
                    patch.object(b, "access_identity", side_effect=[profile, profile]), \
                    patch.object(b, "google_credentials", return_value=refreshed), \
                    patch.object(b, "legacy_subject", return_value=old_subject), \
                    patch.object(b, "build") as calendar:
                response = self.client.get("/google/callback", query_string={"state": oauth["state"], "code": "dummy"})
            calendar.assert_not_called()
            with b.app.app_context():
                stored = b.db.session.get(b.Connection, "employee-a").google_tokens
                if old_subject != "subject-a":
                    self.assertEqual(response.status_code, 400)
                    self.assertEqual(stored, original)
                    self.assertIsNone(b.security_for("employee-a").google_sub)
                else:
                    self.assertEqual(response.status_code, 302)
                    migrated = b.decrypt(stored)
                    self.assertEqual(migrated["_legacy_backup"].encode("ascii"), original)
                    self.assertEqual(migrated["refresh_token"], "new-refresh")
                    self.assertEqual(b.security_for("employee-a").google_sub, "subject-a")
                    self.assertEqual(b.decrypt(migrated["_legacy_backup"].encode("ascii"))["refresh_token"], "old-refresh")

    def test_encrypted_legacy_snapshot_survives_runtime_refresh(self):
        b = self.b
        credentials = Mock(valid=False)
        credentials.to_json.return_value = json.dumps({"token": "fresh", "refresh_token": "safe-refresh"})
        with b.app.app_context():
            row = b.db.session.get(b.Connection, "employee-a")
            original = row.google_tokens.decode("ascii")
            data = b.decrypt(row.google_tokens)
            data["_legacy_backup"] = original
            row.google_tokens = b.encrypt(data)
            b.db.session.commit()
            with patch.object(b, "google_credentials", return_value=credentials), \
                    patch.object(b, "access_identity", return_value={"sub": "subject-a"}), \
                    patch.object(b, "build"):
                b.google_service(row)
            self.assertEqual(b.decrypt(row.google_tokens)["_legacy_backup"], original)

    def test_stale_preview_after_connect_disconnect_and_version_change(self):
        form, _ = self.preview()
        self.authorize_state()
        self.assertEqual(self.client.post("/sync/apply", data=form).status_code, 409)
        form, _ = self.preview()
        with patch.object(self.b.requests, "post", return_value=Mock(status_code=200)):
            self.assertEqual(self.client.post("/google/disconnect", data={"csrf": "test-csrf"}).status_code, 302)
        self.assertEqual(self.client.post("/sync/apply", data=form).status_code, 409)
        form, _ = self.preview()
        with self.b.app.app_context():
            self.b.security_for("employee-a").version = "changed"
            self.b.db.session.commit()
        self.assertEqual(self.client.post("/sync/apply", data=form).status_code, 409)

    def test_expired_changed_destination_and_changed_actions_reject_confirmation(self):
        for change in ("expiry", "subject", "destination", "actions"):
            form, service = self.preview()
            with self.b.app.app_context():
                approval = self.b.db.session.get(self.b.SyncApproval, self.b.digest(form["approval"]))
                if change == "expiry":
                    approval.expires_at = 0
                elif change == "subject":
                    approval.google_sub = "another-account"
                elif change == "destination":
                    approval.destination = "another-calendar"
                self.b.db.session.commit()
            with patch.object(self.b, "google_service", return_value=service), \
                    patch.object(self.b, "build_plan", return_value=(self.actions(), "changed", 1)):
                self.assertEqual(self.client.post("/sync/apply", data=form).status_code, 409)
            service.events.assert_not_called()

    def test_double_confirm_is_consumed_once(self):
        actions = self.actions()
        form, service = self.preview(actions)
        with patch.object(self.b, "google_service", return_value=service), \
                patch.object(self.b, "build_plan", return_value=(actions, "fingerprint-1", 1)):
            self.assertEqual(self.client.post("/sync/apply", data=form).status_code, 200)
            self.assertEqual(self.client.post("/sync/apply", data=form).status_code, 409)
        self.assertEqual(service.events.return_value.insert.call_count, 1)

    def test_cross_user_and_same_user_other_session_cannot_use_approval(self):
        form, _ = self.preview()
        for other in (self.login_client("employee-b", "subject-b"),
                      self.login_client("employee-a", "subject-a")):
            self.assertEqual(other.post("/sync/apply", data=form).status_code, 409)

    def test_overlapping_confirms_across_connections_are_locked(self):
        actions = self.actions()
        form, service = self.preview(actions)
        started, release = threading.Event(), threading.Event()
        def insert_wait():
            started.set()
            if not release.wait(10):
                raise AssertionError("Timed out waiting for duplicate request")
        service.events.return_value.insert.return_value.execute.side_effect = insert_wait
        cookie = self.client.get_cookie(self.b.app.config["SESSION_COOKIE_NAME"]).value
        second = self.b.app.test_client()
        second.set_cookie(self.b.app.config["SESSION_COOKIE_NAME"], cookie)
        responses = []
        with patch.object(self.b, "google_service", return_value=service), \
                patch.object(self.b, "build_plan", return_value=(actions, "fingerprint-1", 1)):
            thread = threading.Thread(target=lambda: responses.append(second.post("/sync/apply", data=form).status_code))
            thread.start()
            try:
                self.assertTrue(started.wait(10))
                self.assertEqual(self.client.post("/sync/apply", data=form).status_code, 409)
            finally:
                release.set()
                thread.join(10)
            self.assertFalse(thread.is_alive())
        self.assertEqual(responses, [200])
        self.assertEqual(service.events.return_value.insert.call_count, 1)

    def test_uncertain_parent_deletion_blocks_but_visible_removed_row_deletes(self):
        b = self.b
        event = dict(self.event(), id="existing-id")
        event["extendedProperties"]["private"]["kintoneKey"] = "1675:999:old"
        record = {"$id": {"value": "123"}, "schedule": {"value": []}}
        employee = SimpleNamespace(user_code="employee-a")
        with b.app.app_context(), patch.object(b, "get_self_records", return_value=[record]), \
                patch.object(b, "google_events", return_value=[event]):
            actions, _, _ = b.build_plan(employee, None)
        self.assertEqual(actions[0]["action"], "BLOCKED")
        form, _ = self.preview(actions)
        self.assertIsNone(form)
        event["extendedProperties"]["private"]["kintoneKey"] = "1675:123:old"
        with b.app.app_context(), patch.object(b, "get_self_records", return_value=[record]), \
                patch.object(b, "google_events", return_value=[event]):
            actions, _, _ = b.build_plan(employee, None)
        self.assertEqual(actions[0]["action"], "DELETE")

    def test_logout_revokes_copied_cookie_approval_and_oauth(self):
        oauth, flow = self.authorize_state()
        form, _ = self.preview()
        cookie_name = self.b.app.config["SESSION_COOKIE_NAME"]
        cookie = self.client.get_cookie(cookie_name).value
        oauth_cookie = self.client.get_cookie(self.b.GOOGLE_STATE_COOKIE, path="/google/callback").value
        copied = self.b.app.test_client()
        copied.set_cookie(cookie_name, cookie)
        copied.set_cookie(self.b.GOOGLE_STATE_COOKIE, oauth_cookie, path="/google/callback")
        self.assertEqual(self.client.post("/logout", data={"csrf": "test-csrf"}).status_code, 200)
        for path, method, data in (("/", "get", {}), ("/sync/apply", "post", form),
                                   ("/google/callback?state=" + oauth["state"] + "&code=dummy", "get", {})):
            response = getattr(copied, method)(path, **({"data": data} if method == "post" else {}))
            self.assertEqual(response.status_code, 302)
            self.assertTrue(response.location.endswith("/login"))
        flow.fetch_token.assert_not_called()
        with self.b.app.app_context():
            self.assertEqual(self.b.SyncApproval.query.count(), 0)
            self.assertEqual(self.b.BrowserSession.query.count(), 0)
            self.assertIsNotNone(self.b.db.session.get(self.b.Connection, "employee-a").google_tokens)

    def test_logout_disconnect_apply_require_post_and_csrf(self):
        for path in ("/logout", "/google/disconnect", "/sync/apply"):
            self.assertEqual(self.client.get(path).status_code, 405)
            self.assertEqual(self.client.post(path).status_code, 403)

    def test_user_code_cookie_without_server_session_is_rejected(self):
        client = self.b.app.test_client()
        with client.session_transaction() as session:
            session["user_code"] = "employee-a"
        self.assertEqual(client.get("/").status_code, 302)

    def test_oauth_session_swap_and_replay_are_blocked(self):
        oauth, flow = self.authorize_state()
        signed = self.client.get_cookie(self.b.GOOGLE_STATE_COOKIE, path="/google/callback").value
        other = self.login_client("employee-b", "subject-b")
        other.set_cookie(self.b.GOOGLE_STATE_COOKIE, signed, path="/google/callback")
        query = {"state": oauth["state"], "code": "dummy"}
        with patch.object(self.b, "google_flow", return_value=flow):
            self.assertEqual(other.get("/google/callback", query_string=query).status_code, 403)
        flow.fetch_token.assert_not_called()
        # A declined callback consumes the pending state and cannot be replayed.
        self.assertEqual(self.client.get("/google/callback", query_string={"state": oauth["state"], "error": "denied"}).status_code, 400)
        self.assertEqual(self.client.get("/google/callback", query_string=query).status_code, 403)

    def test_create_retry_has_stable_id_and_checks_collision_ownership(self):
        b = self.b
        action = self.actions()[0]
        service = Mock()
        service.events.return_value.insert.return_value.execute.side_effect = b.HttpError(
            Response({"status": "409"}), b'{"error":{"message":"exists"}}')
        service.events.return_value.get.return_value.execute.return_value = copy.deepcopy(action["body"])
        with b.app.test_request_context():
            b.create_event(service, action, "employee-a")
            b.create_event(service, action, "employee-a")
            bodies = [call.kwargs["body"] for call in service.events.return_value.insert.call_args_list]
            self.assertEqual(bodies[0]["id"], bodies[1]["id"])
            self.assertRegex(bodies[0]["id"], r"^[0-9a-v]{5,1024}$")
            self.assertNotEqual(bodies[0]["id"], b.deterministic_event_id("employee-b", action["key"]))
            service.events.return_value.get.return_value.execute.return_value["extendedProperties"]["private"][b.SCOPE_TAG] = "employee-b"
            with self.assertRaises(HTTPException) as error:
                b.create_event(service, action, "employee-a")
            self.assertEqual(error.exception.code, 409)
        service.events.return_value.patch.assert_not_called()

    def test_error_content_is_plain_text_and_external_urls_are_not_echoed(self):
        with patch.object(self.b, "google_service", side_effect=ValueError("<script>test</script>")):
            response = self.client.get("/sync/preview")
        self.assertEqual(response.mimetype, "text/plain")
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
        with patch.object(self.b, "google_service", side_effect=self.b.requests.RequestException("token=secret-test")):
            response = self.client.get("/sync/preview")
        self.assertEqual(response.mimetype, "text/plain")
        self.assertNotIn("secret-test", response.get_data(as_text=True))

    def test_dashboard_escapes_verified_account_label(self):
        with self.b.app.app_context():
            self.b.security_for("employee-a").google_label = "<b>test account</b>"
            self.b.db.session.commit()
        response = self.client.get("/")
        self.assertIn("&lt;b&gt;test account&lt;/b&gt;", response.get_data(as_text=True))

    def test_schema_migration_is_additive_idempotent_and_preserves_blobs(self):
        with self.b.app.app_context():
            row = self.b.db.session.get(self.b.Connection, "employee-a")
            before = (row.kintone_tokens, row.google_tokens)
            self.b.db.create_all()
            self.b.db.create_all()
            row = self.b.db.session.get(self.b.Connection, "employee-a", populate_existing=True)
            self.assertEqual(before, (row.kintone_tokens, row.google_tokens))
        with closing(sqlite3.connect(self.path)) as db:
            columns = [row[1] for row in db.execute('PRAGMA table_info("connection")')]
            self.assertEqual(columns, ["user_code", "kintone_tokens", "google_tokens", "updated_at"])

    def test_startup_upgrades_original_schema_without_rewriting_tokens(self):
        path = Path(self.temp.name) / "legacy.db"
        with closing(sqlite3.connect(path)) as db:
            db.execute("CREATE TABLE connection (user_code VARCHAR(150) PRIMARY KEY NOT NULL, "
                       "kintone_tokens BLOB NOT NULL, google_tokens BLOB, updated_at FLOAT)")
            db.execute("INSERT INTO connection VALUES (?, ?, ?, ?)",
                       ("legacy-employee", b"opaque-kintone", b"opaque-google", 123.0))
            db.commit()
        for _ in range(2):
            migrated = tz_tests.load_test_app("sqlite:///" + path.as_posix())
            with migrated.app.app_context():
                migrated.db.session.remove()
                migrated.db.engine.dispose()
        with closing(sqlite3.connect(path)) as db:
            self.assertEqual(db.execute("SELECT * FROM connection").fetchall(),
                             [("legacy-employee", b"opaque-kintone", b"opaque-google", 123.0)])
            names = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            self.assertTrue({"connection", "connection_security", "browser_session", "sync_approval"} <= names)

    def test_kintone_login_rotates_session_and_preserves_google_tokens(self):
        b = self.b
        form, _ = self.preview()
        original_sid = None
        with self.client.session_transaction() as session:
            original_sid = session["sid"]
        with b.app.app_context():
            before = b.db.session.get(b.Connection, "employee-a").google_tokens
        response = self.client.get("/login")
        self.assertEqual(response.status_code, 302)
        signed = self.client.get_cookie(b.KINTONE_STATE_COOKIE, path="/kintone/callback").value
        state = b.kintone_state_signer.loads(signed)
        with b.app.app_context():
            self.assertIsNone(b.db.session.get(b.BrowserSession, b.digest(original_sid)))
            self.assertEqual(b.SyncApproval.query.count(), 0)
        token_response = Mock()
        token_response.json.return_value = {"access_token": "new-kintone", "refresh_token": "refresh"}
        record = {"employee": {"value": [{"code": "employee-a"}]}}
        with patch.object(b.requests, "post", return_value=token_response), \
                patch.object(b, "kintone_records", return_value=[record]) as records:
            response = self.client.get("/kintone/callback", query_string={"state": state, "code": "dummy"})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(records.call_args.args[1], "employee in (LOGINUSER())")
        with self.client.session_transaction() as session:
            self.assertNotEqual(session["sid"], original_sid)
            self.assertEqual(session["user_code"], "employee-a")
        with b.app.app_context():
            self.assertEqual(before, b.db.session.get(b.Connection, "employee-a").google_tokens)
        self.assertEqual(self.client.post("/sync/apply", data=form).status_code, 403)

    def test_get_self_records_rejects_employee_mismatch(self):
        b = self.b
        with patch.object(b, "kintone_token", return_value="offline"), \
                patch.object(b, "kintone_records", return_value=[
                    {"employee": {"value": [{"code": "employee-b"}]}}
                ]) as records:
            with self.assertRaisesRegex(ValueError, "identity mismatch"):
                b.get_self_records(SimpleNamespace(user_code="employee-a"))
            self.assertEqual(records.call_args.args[1], "employee in (LOGINUSER())")

    def test_existing_event_ids_are_used_for_update_and_owned_delete(self):
        update = dict(self.actions()[0], action="UPDATE", eventId="original-event-id")
        delete = dict(update, action="DELETE", key="1675:123:old", eventId="old-event-id", body=None)
        actions = [update, delete]
        form, service = self.preview(actions)
        with patch.object(self.b, "google_service", return_value=service), \
                patch.object(self.b, "build_plan", return_value=(actions, "fingerprint-1", 1)):
            self.assertEqual(self.client.post("/sync/apply", data=form).status_code, 200)
        self.assertEqual(service.events.return_value.patch.call_args.kwargs["eventId"], "original-event-id")
        self.assertEqual(service.events.return_value.delete.call_args.kwargs["eventId"], "old-event-id")
        service.events.return_value.insert.assert_not_called()


if __name__ == "__main__":
    unittest.main()
