"""Offline regression tests. No .env, real database, credentials, or APIs used.

Run with the project environment: python -m unittest -v test_timezones.py
"""

import copy
import importlib.util
import os
from pathlib import Path
import sys
import secrets
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from cryptography.fernet import Fernet


def load_test_app(database_url="sqlite:///:memory:"):
    spec = importlib.util.spec_from_file_location(
        "daikai_timezone_test_app", Path(__file__).with_name("app.py")
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    settings = {
        "PUBLIC_BASE_URL": "https://calendar.example.invalid",
        "KINTONE_BASE_URL": "https://kintone.example.invalid",
        "KINTONE_OAUTH_CLIENT_ID": "offline-test",
        "KINTONE_OAUTH_CLIENT_SECRET": "offline-test",
        "TOKEN_ENCRYPTION_KEY": Fernet.generate_key().decode(),
        "FLASK_SECRET_KEY": "offline-test-only",
        "DATABASE_URL": database_url,
        "GOOGLE_CLIENT_JSON": "unused-offline-test.json",
        "KINTONE_IDENTITY_APP_ID": "",
        "KINTONE_IDENTITY_USER_FIELD": "",
        "KINTONE_CONTROLLED_DELETE_ENABLED": "false",
        "KINTONE_CONTROLLED_DELETE_PERMISSIONS_ACK": "false",
        "KINTONE_DELETE_API_TOKEN": "",
    }
    with patch.dict(os.environ, settings), patch("dotenv.load_dotenv"), patch(
        "requests.sessions.Session.request",
        side_effect=AssertionError("Network access forbidden in offline tests"),
    ), patch(
        "httplib2.Http.request", side_effect=AssertionError("Network access forbidden in offline tests"),
    ):
        spec.loader.exec_module(module)
    module.app.config["TESTING"] = True
    return module


backend = load_test_app()


class TimezoneTests(unittest.TestCase):
    def setUp(self):
        self.network = patch(
            "requests.sessions.Session.request",
            side_effect=AssertionError("Network access forbidden in offline tests"),
        )
        self.network.start()
        self.addCleanup(self.network.stop)
        self.record = {"$id": {"value": "123"}, "$revision": {"value": "1"},
                       "employee": {"value": [{"code": "employee-test"}]}}
        self.employee = SimpleNamespace(user_code="employee-test")

    def row(self, zone="Singapore [Asia/Singapore] — UTC+08:00", **overrides):
        fields = {
            "row_type": "Customer visit",
            "row_status": "Confirmed",
            "row_place": "Customer office",
            "row_from": "2026-11-11",
            "row_to": "2026-11-11",
            "row_start_time": "09:00",
            "row_end_time": "17:30",
            "row_timezone_select": zone,
        }
        fields.update(overrides)
        return {
            "id": "456",
            "value": {key: {"value": value} for key, value in fields.items()},
        }

    def event(self, subrow):
        return backend.row_event(self.record, subrow, self.employee.user_code)

    def plan(self, rows, existing=(), legacy=()):
        record = dict(self.record, schedule={"value": rows})
        with backend.app.app_context(), patch.object(backend, "get_self_records", return_value=[record]), patch.object(
            backend, "google_events", side_effect=lambda service, property_filter: list(
                existing if property_filter.startswith(backend.SCOPE_TAG + "=") else legacy
            )
        ):
            return backend.build_plan(self.employee, None)

    def existing(self, event):
        return dict(copy.deepcopy(event), id="existing-google-id", etag='"offline-etag"')

    def test_country_offsets_and_selected_clocks(self):
        for label, zone, offset in (
            ("Singapore", "Asia/Singapore", "+08:00"),
            ("Vietnam — Hanoi / Hai Phong / Ho Chi Minh", "Asia/Ho_Chi_Minh", "+07:00"),
            ("Japan — Tokyo / Osaka / Yokohama", "Asia/Tokyo", "+09:00"),
            ("Philippines — Manila / Cebu", "Asia/Manila", "+08:00"),
        ):
            with self.subTest(zone=zone):
                event = self.event(self.row(f"{label} [{zone}] — ignored UTC text"))
                self.assertEqual(event["start"], {
                    "dateTime": f"2026-11-11T09:00:00{offset}", "timeZone": zone,
                })
                self.assertEqual(event["end"], {
                    "dateTime": f"2026-11-11T17:30:00{offset}", "timeZone": zone,
                })

    def test_sydney_dst_and_standard_time(self):
        for day, offset in (("2026-11-11", "+11:00"), ("2026-06-11", "+10:00")):
            with self.subTest(day=day):
                event = self.event(self.row(
                    "Australia — Sydney [Australia/Sydney] — UTC+10:00 / UTC+11:00 (DST)",
                    row_from=day, row_to=day,
                ))
                self.assertEqual(event["start"]["dateTime"], f"{day}T09:00:00{offset}")
                self.assertEqual(event["end"]["dateTime"], f"{day}T17:30:00{offset}")
                self.assertEqual(event["start"]["timeZone"], "Australia/Sydney")

    def test_different_zones_in_one_plan(self):
        first = self.row()
        second = self.row("Vietnam [Asia/Ho_Chi_Minh] — UTC+07:00")
        second["id"] = "457"
        actions, _, count = self.plan([first, second])
        self.assertEqual(count, 1)
        self.assertEqual([a["action"] for a in actions], ["CREATE", "CREATE"])
        self.assertTrue(actions[0]["body"]["start"]["dateTime"].endswith("+08:00"))
        self.assertTrue(actions[1]["body"]["start"]["dateTime"].endswith("+07:00"))

    def test_blank_historical_timezone(self):
        for blank in ("", None, "   "):
            with self.subTest(blank=blank):
                self.assertEqual(self.event(self.row(blank)), self.event(self.row()))
        missing = self.row()
        del missing["value"]["row_timezone_select"]
        self.assertEqual(self.event(missing), self.event(self.row()))

    def test_deleted_old_timezone_is_not_read(self):
        event = self.event(self.row(row_timezone="Japan [Asia/Tokyo]"))
        self.assertEqual(event["start"]["timeZone"], "Asia/Singapore")

    def test_invalid_nonempty_timezone(self):
        for invalid in ("Asia/Tokyo", "Japan []", "Bad [Asia/Invalid]", "[../Tokyo]",
                        "[Asia/Tokyo] [Asia/Singapore]", 123):
            with self.subTest(invalid=invalid), self.assertRaisesRegex(
                ValueError, "(Invalid|unavailable).*subtable row 456"
            ):
                self.event(self.row(invalid))

    def test_unavailable_timezone_data_stops_safely(self):
        with patch.object(backend, "ZoneInfo", side_effect=backend.ZoneInfoNotFoundError), \
                self.assertRaisesRegex(ValueError, "installed tzdata"):
            self.event(self.row())

    def test_ambiguous_and_nonexistent_start_and_end(self):
        for day, reason in (("2026-04-05", "Ambiguous"), ("2026-10-04", "Nonexistent")):
            for endpoint in ("row_start_time", "row_end_time"):
                with self.subTest(day=day, endpoint=endpoint):
                    fields = dict(row_from=day, row_to=day, row_start_time="00:30",
                                  row_end_time="04:00")
                    fields[endpoint] = "02:30"
                    with self.assertRaisesRegex(ValueError, reason + ".*Australia/Sydney.*456"):
                        self.event(self.row("Sydney [Australia/Sydney]", **fields))

    def test_multiday_across_dst_keeps_explicit_dates(self):
        event = self.event(self.row(
            "Sydney [Australia/Sydney]", row_from="2026-10-03", row_to="2026-10-05",
        ))
        self.assertEqual(event["start"]["dateTime"], "2026-10-03T09:00:00+10:00")
        self.assertEqual(event["end"]["dateTime"], "2026-10-05T17:30:00+11:00")

    def test_invalid_dates_times_and_order(self):
        for fields in ({"row_from": "2026-02-30"}, {"row_to": "bad-date"},
                       {"row_start_time": "25:00"}, {"row_end_time": ""},
                       {"row_end_time": "08:00"}, {"row_end_time": "09:00"},
                       {"row_to": "2026-11-10"}):
            with self.subTest(fields=fields), self.assertRaises(ValueError):
                self.event(self.row(**fields))

    def test_timezone_change_updates_same_event_id_key_and_metadata(self):
        original = self.event(self.row())
        current = self.existing(original)
        changed = self.row("Vietnam [Asia/Ho_Chi_Minh] — UTC+07:00")
        actions, changed_fingerprint, _ = self.plan([changed], [current])
        unchanged, original_fingerprint, _ = self.plan([self.row()], [current])
        self.assertEqual(unchanged[0]["action"], "UNCHANGED")
        self.assertEqual(actions[0]["action"], "UPDATE")
        self.assertEqual(actions[0]["eventId"], "existing-google-id")
        self.assertEqual(actions[0]["key"], "1675:123:456")
        for field in ("summary", "description", "extendedProperties"):
            self.assertEqual(actions[0]["body"][field], original[field])
        self.assertNotEqual(changed_fingerprint, original_fingerprint)

    def test_equal_instants_still_match(self):
        desired = self.event(self.row())
        current = copy.deepcopy(desired)
        current["start"] = {"dateTime": "2026-11-11T01:00:00Z"}
        current["end"] = {"dateTime": "2026-11-11T09:30:00Z"}
        self.assertTrue(backend.equal_event(current, desired))

    def test_duplicate_row_and_google_event_prevention(self):
        with self.assertRaisesRegex(ValueError, "Duplicate row ID"):
            self.plan([self.row(), self.row()])
        current = self.existing(self.event(self.row()))
        with self.assertRaisesRegex(ValueError, "Duplicate or invalid Google sync metadata"):
            self.plan([self.row()], [current, current])
        with self.assertRaisesRegex(ValueError, "Duplicate legacy events"):
            self.plan([self.row()], legacy=[current, current])

    def test_legacy_matching_preserves_id_and_updates_tag(self):
        current = self.existing(self.event(self.row()))
        del current["extendedProperties"]["private"][backend.SCOPE_TAG]
        actions, _, _ = self.plan([self.row()], legacy=[current])
        self.assertEqual(actions[0]["action"], "UPDATE")
        self.assertEqual(actions[0]["eventId"], current["id"])

    def test_only_owned_events_are_deleted(self):
        owned = self.existing(self.event(self.row()))
        owned["extendedProperties"]["private"]["kintoneKey"] = "1675:123:789"
        unrelated = copy.deepcopy(owned)
        unrelated["extendedProperties"]["private"] = {"kintoneKey": "unrelated"}
        actions, _, _ = self.plan([self.row()], [owned, unrelated])
        self.assertEqual([(a["key"], a["action"]) for a in actions],
                         [("1675:123:456", "CREATE"), ("1675:123:789", "DELETE")])

    def test_cancelled_and_other_activity_rows_still_skipped(self):
        self.assertIsNone(self.event(self.row("invalid", row_status="Cancelled")))
        self.assertIsNone(self.event(self.row("invalid", row_type="Other")))

    def test_invalid_row_stops_before_google_event_lookup(self):
        record = dict(self.record, schedule={"value": [self.row("invalid")]})
        with backend.app.app_context(), patch.object(backend, "get_self_records", return_value=[record]), \
                patch.object(backend, "google_events") as lookup:
            with self.assertRaises(ValueError):
                backend.build_plan(self.employee, None)
            lookup.assert_not_called()

    def test_preview_returns_clear_errors_without_confirmation(self):
        for invalid in (self.row("Bad [Asia/Invalid]"), self.row(row_from="2026-02-30"),
                        self.row("Sydney [Australia/Sydney]", row_from="2026-10-04",
                                 row_to="2026-10-04", row_start_time="02:30")):
            with self.subTest(row=invalid):
                record = dict(self.record, schedule={"value": [invalid]})
                with backend.app.test_client() as client:
                    sid = secrets.token_urlsafe(32)
                    with backend.app.app_context():
                        backend.db.session.add(backend.BrowserSession(
                            sid_hash=backend.digest(sid), user_code=self.employee.user_code,
                            expires_at=time.time() + 3600
                        ))
                        backend.db.session.commit()
                    with client.session_transaction() as session:
                        session["user_code"] = self.employee.user_code
                        session["sid"] = sid
                    with patch.object(backend, "stored", return_value=self.employee), \
                            patch.object(backend, "google_service", return_value=object()), \
                            patch.object(backend, "get_self_records", return_value=[record]), \
                            patch.object(backend, "google_events") as lookup:
                        response = client.get("/sync/preview")
                    self.assertEqual(response.status_code, 502)
                    self.assertIn("Preview stopped safely: ValueError", response.get_data(as_text=True))
                    self.assertNotIn("Confirm sync", response.get_data(as_text=True))
                    lookup.assert_not_called()
                    with client.session_transaction() as session:
                        self.assertNotIn("fingerprint", session)


if __name__ == "__main__":
    unittest.main()
