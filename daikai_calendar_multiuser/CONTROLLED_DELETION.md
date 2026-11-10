# Controlled monthly-record deletion: backend phases 1–6, Option B POC

Status: implemented for offline validation; **disabled by default and not production approved**.
No Kintone configuration or production data changes are performed by this code change.

**Option B:** leave `KINTONE_IDENTITY_APP_ID` and `KINTONE_IDENTITY_USER_FIELD`
blank. Employee identity continues to come from OAuth-authenticated, correctly
owned App 1675 records. Preparation and confirmation freshly retrieve and validate
the employee's complete accessible records; the final accessible monthly record
cannot be deleted, even when its schedule is empty. Retain at least one other
correctly owned record with no pending/uncertain deletion. Client counts are ignored.
The final check runs after snapshot/manifest checks and before DELETE dispatch.
Lost visibility, incomplete retrieval or an inaccessible target blocks deletion.
Native Kintone permission changes/deletions can still race with these reads, so
the permission restrictions below are required; Flask locks do not control Kintone UI edits.

Offline verification on 2026-11-10: syntax compilation passed for all five Python
files; all **137 tests passed** (73 existing regressions and 64 controlled-deletion
tests), with ResourceWarning treated as an error. Tests prohibit real network
requests and use in-memory or disposable SQLite databases. Coverage includes an
additive upgrade preserving existing connection/token bytes, concurrent confirms,
partial failures, stale approvals across sessions, zero-record login/cleanup,
employee isolation, timezone regressions and legacy quarantine. Option B coverage
also verifies final-record prevention at preparation and final dispatch, malformed
or partial retrieval, ignored client counts, retained-record login, simultaneous
CREATE/UPDATE/UNCHANGED/DELETE across months, customer/activity/timezone changes,
stable event IDs, Plan/Actual eligibility and row deletion within the final month.

## Behavior and safety boundaries

- Normal row removal uses a fully retrieved, currently owned monthly record. Only
  the event with the exact removed row key is proposed for deletion. Existing
  cancellation and activity eligibility behavior remains in place.
- Missing parents without confirmed evidence remain BLOCKED. Retrieval errors,
  missing fields, warnings, malformed tables, reassignment and pagination failures
  never authorize deletion.
- Employee identity can be verified independently of App 1675 through a protected
  identity app. If both identity settings are blank, original monthly-record login
  and zero-record safeguards remain. Partial configuration fails closed.
- Whole-record deletion requires a prepared operation bound to the current session,
  employee, verified Google subject, destination and connection version. It reads
  the exact record through employee OAuth and a server credential, compares the
  snapshots, then sends revision-checked Kintone DELETE for one record.
- Google changes still require Preview → Confirm Sync. Deleting in Kintone does
  not write Google. Confirmed tombstones authorize only their frozen event manifest.
- Mapping and cleanup state are durable, scoped to tenant/app/record/row, employee,
  source generation, Google subject and calendar destination. Untagged legacy
  events are never deleted. Existing reviewed visible-row legacy adoption and
  quarantine protections remain.
- Google mutation requests use the actual mapped event ID; UPDATE and DELETE use
  If-Match after an exact ownership/key/version check. CREATE uses the existing
  deterministic ID and verifies the resulting event before journaling success.

## Additive schema

Four new tables are registered before the existing serialized create-all step:

| Table | Purpose |
| --- | --- |
| `source_record` | Tenant/app/record identity, employee ownership, immutable generation, revision, durable record lock and active operation |
| `event_mapping` | Actual Google event ID, record/row IDs, employee, subject/destination, source generation/revision and ACTIVE/DELETED state |
| `record_deletion` | Operation ID, session/connection binding, source snapshot hash, frozen mapping manifest/hash, timestamps, state and success receipt |
| `event_cleanup` | Per-event PENDING/UNKNOWN/DONE progress and attempted Google ETag, optionally bound to a record tombstone |

Primary keys and a unique employee/subject/calendar/event constraint prevent
duplicate mappings. New tables use foreign keys. Existing tables and encrypted
token blobs are not altered. Schema creation is additive and idempotent; startup
does not backfill mappings or rewrite existing connection data. Existing files
were not opened by the implementation/test run; tests use disposable databases.

Existing tagged events are journaled after a successful normal confirmed sync,
including verified UNCHANGED events. Whole-record preparation refuses unmapped
events or eligible unsynchronized rows. Run normal sync before first deletion.

## Required environment configuration

| Variable | Default | Required meaning |
| --- | --- | --- |
| `KINTONE_IDENTITY_APP_ID` | blank | Not required for Option B; leave blank in this POC |
| `KINTONE_IDENTITY_USER_FIELD` | blank | Not required for Option B; leave blank in this POC |
| `KINTONE_CONTROLLED_DELETE_ENABLED` | `false` | Explicit `true` enables the backend deletion routes |
| `KINTONE_CONTROLLED_DELETE_PERMISSIONS_ACK` | `false` | Set `true` only after the permission checklist below is verified |
| `KINTONE_DELETE_API_TOKEN` | blank | Server-only App 1675 View records + Delete records API token |

The identity field code currently accepts ASCII letters/digits/underscore and must
start with a letter or underscore. Choose and approve that code in Kintone; no
production ID or field code is supplied by this implementation. Numeric IDs in
offline tests belong solely to disposable fixtures.

Employee OAuth stays `k:app_record:read`. Google scopes, verified-account binding,
encrypted tokens, session revocation, approval lifetime and connection locks stay
in place. Store the delete token in the server secret store, never JS or a browser.
No runtime Kintone app-management or system-administration permission is required.

## Optional independent identity design (not required for Option B)

Skip this section for the Option B POC; do not create an identity app. The existing
optional configuration remains supported for compatibility, but controlled
deletion now always retains another accessible monthly record. Zero-record login
through an already configured protected identity app is a separate existing feature.

1. An authorized administrator creates a separate employee identity app. Record its
   actual app ID for `KINTONE_IDENTITY_APP_ID`.
2. Add a User selection field with an approved ASCII field code. Configure it to
   identify exactly one employee per identity record; set it required and configure
   selectable users so `LOGINUSER()` works in queries. Record its actual field code
   for `KINTONE_IDENTITY_USER_FIELD`.
3. Administrators provision exactly one identity record per allowed employee.
   There must be no duplicate or multi-user identity records. The backend requires
   exactly one result from `<configured field> in (LOGINUSER())` and exactly one
   user code in that result.
4. Give employees View permission for their own identity record and its User
   selection field. Deny employee Add, Edit, Delete, file import, and Manage app
   permissions. Use record permissions to limit visibility to the selected user
   and designated administrators. Deny broader inherited grants.
5. Allow only designated trusted administrators to provision/edit identities and
   manage this app. Inventory API tokens and integrations: none accessible to
   employees may add/edit/delete identity records or alter permissions. API-token
   permissions override ordinary app/record/field permissions.
6. Deploy the app settings, then set both environment variables. Confirm that the
   existing OAuth client can read this app as the employee under its read scope.
7. Test two employees, duplicate identities, missing identities, hidden fields,
   multi-user values and an employee with zero App 1675 records. All ambiguous or
   inaccessible identity cases must fail; no browser user code is accepted.

The backend cannot remotely prove that these permissions are correctly configured.
Configuration review and live sandbox tests are mandatory before use.

## Additional Kintone changes before enabling record deletion

1. Deny App 1675 Delete records permission to ordinary users/groups and interactive
   integration identities, accounting for effective app/record permission rules.
2. Disable native bulk deletion. Verify native detail/list/mobile UI and REST
   DELETE, bulkRequest, CLI, plugins and other integrations cannot bypass the backend.
   Disabling the bulk UI alone does not block REST deletion.
3. Revoke/restrict competing delete-capable API tokens and service credentials.
   Denying employee deletion does not restrict a separately privileged API token.
4. Generate a dedicated App 1675 API token with only View records and Delete
   records. Do not grant Add/Edit/Manage app. Install it only as the server secret.
5. Verify employee and service reads expose the same complete source snapshot;
   differing field visibility blocks deletion instead of bypassing employee access.
6. Restrict app/credential administration. Unrestricted administrators remain a
   trusted boundary and can bypass any configuration they control.
7. Verify these controls before acknowledging them through the environment flag.

## Backend endpoint contract

No Kintone button or new browser deletion interface is installed in phases 1–6.
These POST endpoints are for a subsequently reviewed same-origin client; neither
GET nor a cross-origin request is a deletion interface. Use the application's
existing CSRF token and authenticated browser session.

1. `POST /records/<record_id>/delete/prepare`, form `csrf`.
   Returns operation ID, record/revision, state, manifest hash, exact event keys/IDs,
   event count and expiry (five minutes). Preparation writes no Kintone/Google data.
   A complete calendar scan checks for keyed legacy/foreign/duplicate events.
2. Present the monthly record and exact affected events for deliberate review.
3. `POST /records/<record_id>/delete`, form `csrf`, `operation_id`.
   Rechecks identity, snapshots, mappings and freshly retrieved retained-record
   eligibility; revision-checked DELETE runs once. If the remaining record is lost
   after preparation, the request fails before dispatch and remains PREPARED.
   Response is CONFIRMED (200), UNKNOWN (409), or a safe validation/error response.
4. Open `/sync/preview`, review the Google DELETE actions, and submit the existing
   Confirm Sync form. Approval cannot be reused across sessions/accounts or after
   connection/evidence changes. Apply rebuilds the plan before any Google writes.

Preparation of an already pending/confirmed record returns conflict. Expired,
never-dispatched PREPARED operations can be superseded by another prepare. Execute
replays of CONFIRMED or UNKNOWN return their state without another Kintone DELETE.

## Failure and recovery policy

PREPARED is committed before external deletion. Immediately before dispatch,
UNKNOWN is committed as a durable in-flight fence. Only HTTP 200 with the documented
empty JSON response, without a truncation warning, commits CONFIRMED and its cleanup
rows. Rejections are conservatively UNKNOWN too. Failure before dispatch leaves
PREPARED. A process kill after dispatch cannot leave an executable PREPARED request.

Kintone success and local DB confirmation cannot be one transaction. A lost response
or failed commit leaves unresolved evidence. Missing records, 403/404, empty lists
and retry failures never resolve it. No recovery endpoint or automatic audit-log
ingestion is supplied. Operator-reviewed positive evidence and a separately
reviewed recovery procedure are required. Never manually relabel UNKNOWN merely
because a record is absent.

Google cleanup commits UNKNOWN before each request and DONE after success. A fresh
Preview retries events still positively present. If the event disappeared after a
timeout, recovery requires an exact cancelled event carrying the expected owner,
source key and ID, plus a durable prior UNKNOWN attempt. A bare 404/410 or stripped
Google tombstone stays blocked for review. Already completed mappings are not
deleted again. New previews are required after partial failures; approvals remain
consumed. Confirmed tombstones remain durable after cleanup.

Both employee and source-record CAS locks are durable and non-expiring. Always
acquire employee first, source second; do not hold SQL transactions over network
calls. A killed worker may leave a lock requiring operator review. Do not blindly
clear locks while a writer may still be running.

Native Kintone edits are outside Flask locks. Revision-checked deletion catches
edits/reassignment before Kintone accepts DELETE. Row sync re-reads the exact owned
record before every action and uses Google conditional writes; there is no atomic
transaction spanning a native Kintone edit and a Google operation. Identity/record
permissions must protect reassignment; conflicting ownership is blocked for review.

## Manual deployment and end-to-end checklist (not performed)

- [ ] Review the code and this configuration with Kintone administrators.
- [ ] Back up source and database; test additive schema creation on a disposable
      database copy. Existing source backups are under `source_backups/pre_controlled_delete_*`.
- [ ] Run offline checks from the project folder:
      `python -m py_compile app.py controlled_delete.py test_security.py test_timezones.py test_controlled_delete.py`
      and `python -m unittest discover -s . -p "test_*.py" -v`.
- [ ] Package both `app.py` and `controlled_delete.py` (Dockerfile includes both).
      Preserve all existing OAuth/session/encryption secrets and deployment settings.
- [ ] Leave both identity app settings blank for Option B. Test movement-record
      login, logout/session revocation and ambiguous ownership in an approved sandbox.
- [ ] Apply/verify App 1675 permission changes and inventory every deletion route.
- [ ] Configure the backend credential, verify reads and revision conflicts, then
      explicitly enable the feature in the approved sandbox only.
- [ ] Complete normal Preview/Confirm Sync to journal existing managed events.
- [ ] Test row removal: one exact DELETE, other rows and other employees unchanged.
- [ ] Prepare/delete a monthly record; verify genuine Kintone removal and no Google
      writes until Preview/Confirm Sync. Verify every managed event is listed.
- [ ] Try deleting the final accessible month, including an empty one: expect a
      conflict before Kintone DELETE. Delete one of two months, retain the other,
      sign out/back in, then preview/confirm cleanup. Repeat sync: no extra mutations.
- [ ] Test permission loss, reassignment, missing fields, incomplete pagination,
      revision races, stale approvals, concurrent sessions and competing employees.
- [ ] Inject ambiguous Kintone/Google failures in sandbox; verify UNKNOWN, replay
      prevention, partial cleanup and conservative operator-review boundaries.
- [ ] Recheck timezone conversions, legacy adoption/quarantine and account binding.
- [ ] Review recovery operations, monitoring, retention, backups and production
      database/worker behavior before separately authorizing production rollout.

Neither live permission enforcement, actual service credential privileges, audit
recovery, production worker behavior nor real API responses were certified by
offline tests. Full-calendar scanning can be expensive for large calendars; start
with a limited pilot. Events without source keys cannot safely be attributed by
title or description and are never guessed into a deletion manifest.
