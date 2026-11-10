# Daikai Calendar Sync — Multi-employee pilot (R04)

**Status: local multi-employee pilot code, not production approved.** It is not a drop-in replacement for the working all-month single-user POC. Keep the old files backed up. There are TWO distinct OAuth integrations: Kintone verifies the employee, then Google grants calendar access. The Kintone `employee in (LOGINUSER())` query ensures the backend only reads that employee's own schedule records.

## Important safeguards

- Each person must authorize both Kintone and Google. Kintone's OAuth token limits data to that person's accessible records and `LOGINUSER()`-matched employee records.
- The browser-supplied `kintone.getLoginUser()` is **never used to authenticate backend requests**. The backend derives employee identity from Kintone's OAuth-authorized API response.
- The browser session uses a **stable** Flask secret key; OAuth state is verified against the signed session cookie. The previous unbound server-state fallback is intentionally removed.
- OAuth tokens are encrypted in the DB with Fernet; the encryption key must be outside source control.
- `Connect` is optional. Disconnect revokes Google authorization and removes the stored Google tokens, but leaves already created calendar events alone.
- `Sync Now` opens a preview; writes are done only after a CSRF-protected POST and a freshly recalculated plan.
- Deletes only events with this user's `daikaiCalendarV2` metadata. Untagged legacy POC events can be recognized and adopted for *existing* Kintone rows, but are not deleted as orphan events.
- No auto sync/background worker/webhooks in this pilot. This version uses Singapore time for everyone; adapt each employee's time zone before overseas rollout.
- A Kintone query using `LOGINUSER()` cannot work if the `employee` user selection field is configured with preset selectable users preventing functions; check form field configuration if it errors.

## 1. Local prerequisites

1. Preserve the **working POC** by backing up your original `app.py` and existing `kintone_calendar_ui.js`.
2. Copy all files in this folder into a **new** VS Code folder, e.g. `Kintone-Calendar-Multiuser`.
3. Use Windows PowerShell: `py -m venv .venv`, then `.\.venv\Scripts\python.exe -m pip install -r requirements.txt`; or activate your environment and run `python -m pip install -r requirements.txt`.
4. Keep the OAuth client Google JSON in `client_secret.json` (never commit it). Your existing Google web client is reusable for local testing.
5. Copy `.env.example` to `.env`. Make up new random values; do not reuse insecure defaults:
   - `python -c "import secrets; print(secrets.token_hex(32))"` for `FLASK_SECRET_KEY`.
   - `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"` for `TOKEN_ENCRYPTION_KEY`.
6. `.env` remains private. Do **not** paste secrets into chat or commit them to Git.

## 2. Register a separate Kintone OAuth client

In Kintone: **User & System Administration → OAuth → Add OAuth Client**.

- Name: `Daikai Calendar Pilot`
- Redirect endpoint: `http://localhost:8080/kintone/callback` for local testing, **if your Kintone domain accepts localhost redirects**. If it requires HTTPS, use a dedicated approved HTTPS development endpoint; don't bypass redirect restrictions.
- After saving, record the `KINTONE_OAUTH_CLIENT_ID` and `KINTONE_OAUTH_CLIENT_SECRET` in `.env`.
- Under **Configure users**, allow only the pilot tester initially.
- Scope requested by the code: `k:app_record:read`.

This differs from the separate **Google OAuth client** configured in Google Cloud.

## 3. Update Google OAuth redirect URI

In Google Cloud → Google Auth Platform → Clients → your **Web application** OAuth client, add the authorized redirect URI:

`http://localhost:8080/google/callback`

You may keep your earlier `/oauth2callback` for your existing POC, but the NEW pilot uses `/google/callback`. Keep `calendar.events` scope and your own account under Audience → Test users. Note: External apps in Testing with calendar scope generally issue refresh tokens that expire after **7 days**; move to an appropriate verified/approved production configuration before rollout.

## 4. Start and test locally

1. Ensure `.env` contains Kintone base URL, both Kintone OAuth credentials, `FLASK_SECRET_KEY`, `TOKEN_ENCRYPTION_KEY`, and `DATABASE_URL=sqlite:///pilot.db`.
2. Run `python -m py_compile app.py` and `python app.py`.
3. Visit **only** `http://localhost:8080/login` (not `127.0.0.1`) from the same Chrome profile.
4. Authorize **Kintone**; the backend will discover the single employee code from records returned under `employee in (LOGINUSER())`. The pilot requires that employee to have at least one movement record.
5. Click **Connect Google Calendar**; authorize Google; verify status Connected.
6. Click **Preview Sync (All Months)**, inspect proposed CREATE/UPDATE/DELETE counts, then click Confirm Sync.
7. Revisit Preview Sync and check everything is UNCHANGED. Test a new row, a time edit, then a cancelled/deleted test row.
8. Click **Disconnect Google**; no future sync is possible until reconnection. Existing events are retained.

If authorization fails with a state mismatch, ensure you started at `localhost`, the Flask secret is constant, and a fresh callback is used. Do not reintroduce the older unbound OAuth-state fallback.

## 5. Kintone buttons

Use the included `kintone_calendar_ui.js`, replacing the older calendar UI script only. This script uses `getHeaderSpaceElement()` so it does not overlap your AM/PM and Monthly grid toolbars. For the local pilot, it displays buttons **only** for `PILOT_EMAIL` and opens local Flask, which can work only on that tester's PC. Leave the existing AM/PM grid and Monthly grid JavaScript unchanged.

## 6. Company server deployment architecture (not performed by this package)

Recommended AWS design:

`Kintone JS → HTTPS DNS + ALB → ECS Fargate Gunicorn Flask → RDS PostgreSQL`

- Configure company-controlled TLS certificate and HTTPS DNS, e.g. `https://calendar-sync.daikai.com` (illustrative; DNS must actually exist).
- Use **RDS PostgreSQL**, not SQLite. Set `DATABASE_URL=postgresql+psycopg://...` as a protected secret and run the DB migration/init in a controlled deployment step.
- Keep `FLASK_SECRET_KEY`, `TOKEN_ENCRYPTION_KEY`, Kintone OAuth client secret and Google client JSON in an appropriate secret store (AWS Secrets Manager); grant least-privilege access to the ECS task role. Do not put them in the Docker image, JS, or Git.
- Configure `PUBLIC_BASE_URL=https://your-real-domain`; update **both** Kintone and Google OAuth callback URIs to `${PUBLIC_BASE_URL}/kintone/callback` and `${PUBLIC_BASE_URL}/google/callback`.
- Update `BACKEND` in `kintone_calendar_ui.js` to the actual HTTPS hostname. Verify Kintone organization's outbound access and allowlists/CSP requirements if applicable.
- Use the included Dockerfile as a deployment starting point; do not use `python app.py` as a production WSGI server.
- Configure ECS service health checks to `/health`, DB backups, logging, alerting, secret rotation procedures, and access controls.
- Before scaling: add database migrations, robust refresh/reconnect error handling, tenant monitoring, request throttling, replay protection, proper account-switch logout and session invalidation, concurrency-safe DB writes, and a Kintone/Google security review.
- **Do not enable multi-employee access until security review and these prerequisites are completed.**

## 7. Beyond this pilot

- **Automatic sync:** Kintone webhooks + authenticated job queue and a periodic reconciliation worker. Webhooks can be missed; treat sync as idempotent. A webhook alone should not trust a claimed employee code.
- **Time zones:** use Kintone user/employee timezone instead of assuming Singapore for overseas branches.
- **Plan / Actual:** define policy for whether both should create calendar events or only the effective schedule; current code includes both eligible schedule rows independently.
- **All day / AM/PM:** design proper fallback where explicit start/end times are missing.
- **OAuth consent:** production Google OAuth sensitive scope may require verification, privacy/terms URLs, and organizational approval.
