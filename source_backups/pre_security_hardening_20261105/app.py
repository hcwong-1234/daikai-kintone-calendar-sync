
"""Daikai Calendar Sync - Multiuser Pilot.

Kintone employee OAuth + Google Calendar OAuth + manual sync.
Pilot only. Security review required before production rollout.
"""

import os
import json
import secrets
import hashlib
import hmac
import time
import logging
import re

from datetime import datetime, timezone, timedelta
from urllib.parse import urlencode
from functools import wraps
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import requests

from cryptography.fernet import Fernet
from dotenv import load_dotenv
from flask import (
    Flask, request, session, redirect,
    url_for, render_template_string, abort
)
from flask_sqlalchemy import SQLAlchemy
from itsdangerous import (
    URLSafeTimedSerializer,
    BadSignature,
    SignatureExpired
)
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from googleapiclient.discovery import build


# ============================================================
# CONFIGURATION
# ============================================================

load_dotenv()

BASE = os.environ.get(
    "PUBLIC_BASE_URL", "http://localhost:8080"
).rstrip("/")

if not (
    BASE.startswith("https://")
    or BASE == "http://localhost:8080"
):
    raise RuntimeError(
        "PUBLIC_BASE_URL must use HTTPS."
    )

KINTONE = os.environ.get(
    "KINTONE_BASE_URL", ""
).rstrip("/")

if not KINTONE.startswith("https://"):
    raise RuntimeError(
        "KINTONE_BASE_URL must start with https://"
    )

K_CLIENT = os.environ["KINTONE_OAUTH_CLIENT_ID"]
K_SECRET = os.environ["KINTONE_OAUTH_CLIENT_SECRET"]

GOOGLE_JSON = Path(
    os.environ.get(
        "GOOGLE_CLIENT_JSON",
        "client_secret.json"
    )
)

GOOGLE_SCOPE = [
    "https://www.googleapis.com/auth/calendar.events"
]

APP_ID = 1675
SCOPE_TAG = "daikaiCalendarV2"

KEY = Fernet(
    os.environ["TOKEN_ENCRYPTION_KEY"].encode()
)


# ============================================================
# FLASK
# ============================================================

app = Flask(__name__)

app.secret_key = os.environ["FLASK_SECRET_KEY"]

app.config.update(
    SQLALCHEMY_DATABASE_URI=os.environ.get(
        "DATABASE_URL",
        "sqlite:///pilot.db"
    ),
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    SESSION_COOKIE_NAME="daikai_calendar_pilot_v2",
    SESSION_COOKIE_SECURE=BASE.startswith("https://"),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
)


# ============================================================
# OAUTH STATE COOKIES
# ============================================================

KINTONE_STATE_COOKIE = "daikai_kintone_oauth_state"
GOOGLE_STATE_COOKIE = "daikai_google_oauth_state"

kintone_state_signer = URLSafeTimedSerializer(
    app.secret_key,
    salt="daikai-kintone-oauth-state-v1"
)

google_state_signer = URLSafeTimedSerializer(
    app.secret_key,
    salt="daikai-google-oauth-state-v1"
)


# ============================================================
# SAFE LOGGING
# ============================================================

class RedactOAuthQuery(logging.Filter):

    def filter(self, record):
        if "/callback?" in record.getMessage():
            record.msg = (
                "OAuth callback received "
                "(query parameters omitted)"
            )
            record.args = ()

        return True


logging.getLogger("werkzeug").addFilter(
    RedactOAuthQuery()
)


# ============================================================
# DATABASE
# ============================================================

db = SQLAlchemy(app)


class Connection(db.Model):

    user_code = db.Column(
        db.String(150),
        primary_key=True
    )

    kintone_tokens = db.Column(
        db.LargeBinary,
        nullable=False
    )

    google_tokens = db.Column(
        db.LargeBinary,
        nullable=True
    )

    updated_at = db.Column(
        db.Float,
        default=time.time
    )


with app.app_context():
    db.create_all()


# ============================================================
# SECURITY HELPERS
# ============================================================

def encrypt(value):
    return KEY.encrypt(
        json.dumps(value).encode()
    )


def decrypt(value):
    return json.loads(
        KEY.decrypt(value).decode()
    )


def csrf():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(24)

    return session["csrf"]


def check_csrf():
    expected = session.get("csrf")
    provided = request.form.get("csrf", "")

    if (
        not expected
        or not hmac.compare_digest(provided, expected)
    ):
        abort(403)


def require_login(function):

    @wraps(function)
    def inner(*args, **kwargs):

        if not session.get("user_code"):
            return redirect(
                url_for("login_kintone")
            )

        return function(*args, **kwargs)

    return inner


def stored():
    return db.session.get(
        Connection,
        session["user_code"]
    )


# ============================================================
# KINTONE API
# ============================================================

def kintone_token(row):

    token_data = decrypt(row.kintone_tokens)

    if time.time() > token_data.get("expires_at", 0) - 90:

        response = requests.post(
            KINTONE + "/oauth2/token",
            auth=(K_CLIENT, K_SECRET),
            data={
                "grant_type": "refresh_token",
                "refresh_token": token_data["refresh_token"]
            },
            timeout=15
        )

        response.raise_for_status()
        new_tokens = response.json()

        token_data.update(new_tokens)

        token_data["expires_at"] = (
            time.time() + new_tokens.get("expires_in", 3600)
        )

        row.kintone_tokens = encrypt(token_data)
        db.session.commit()

    return token_data["access_token"]


def kintone_records(access_token, query):

    records = []
    last_record_id = 0

    while True:

        full_query = (
            query
            + f" and $id > {last_record_id}"
            + " order by $id asc limit 500"
        )

        response = requests.get(
            KINTONE + "/k/v1/records.json",
            headers={
                "Authorization": "Bearer " + access_token
            },
            params={
                "app": APP_ID,
                "query": full_query
            },
            timeout=25
        )

        response.raise_for_status()

        data = response.json()["records"]
        records.extend(data)

        if len(data) < 500:
            return records

        last_record_id = int(
            data[-1]["$id"]["value"]
        )


def get_self_records(row):

    records = kintone_records(
        kintone_token(row),
        "employee in (LOGINUSER())"
    )

    for record in records:

        users = record["employee"]["value"]

        if (
            len(users) != 1
            or users[0]["code"] != row.user_code
        ):
            raise ValueError(
                "Kintone employee identity mismatch. "
                "Synchronization stopped."
            )

    return records


# ============================================================
# GOOGLE API
# ============================================================

def google_service(row):

    if row is None or row.google_tokens is None:
        return None

    token_data = decrypt(row.google_tokens)

    client = json.loads(
        GOOGLE_JSON.read_text(encoding="utf-8")
    )["web"]

    credentials = Credentials.from_authorized_user_info(
        {
            "token": token_data.get("token"),
            "refresh_token": token_data.get("refresh_token"),
            "token_uri": "https://oauth2.googleapis.com/token",
            "client_id": client["client_id"],
            "client_secret": client["client_secret"],
            "scopes": GOOGLE_SCOPE,
            "expiry": token_data.get("expiry")
        },
        scopes=GOOGLE_SCOPE
    )

    if not credentials.valid:

        credentials.refresh(Request())

        row.google_tokens = encrypt(
            json.loads(credentials.to_json())
        )

        db.session.commit()

    return build(
        "calendar",
        "v3",
        credentials=credentials,
        cache_discovery=False
    )


def google_flow(state=None):

    flow = Flow.from_client_secrets_file(
        str(GOOGLE_JSON),
        scopes=GOOGLE_SCOPE,
        state=state
    )

    flow.redirect_uri = BASE + "/google/callback"

    return flow


# ============================================================
# KINTONE OAUTH LOGIN
# ============================================================

@app.route("/login")
def login_kintone():

    session.clear()

    state = secrets.token_urlsafe(28)

    params = urlencode({
        "client_id": K_CLIENT,
        "response_type": "code",
        "redirect_uri": BASE + "/kintone/callback",
        "scope": "k:app_record:read",
        "state": state
    })

    response = redirect(
        KINTONE + "/oauth2/authorization?" + params
    )

    response.set_cookie(
        KINTONE_STATE_COOKIE,
        kintone_state_signer.dumps(state),
        max_age=600,
        path="/kintone/callback",
        secure=BASE.startswith("https://"),
        httponly=True,
        samesite="Lax"
    )

    return response


# ============================================================
# KINTONE OAUTH CALLBACK
# ============================================================

@app.route("/kintone/callback")
def kintone_callback():

    provided_state = request.args.get("state", "")

    signed_cookie = request.cookies.get(
        KINTONE_STATE_COOKIE
    )

    if not signed_cookie:
        abort(
            403,
            "Kintone OAuth cookie missing. "
            "Start again from /login."
        )

    try:
        expected_state = kintone_state_signer.loads(
            signed_cookie,
            max_age=600
        )

    except SignatureExpired:
        abort(403, "Kintone OAuth login expired.")

    except BadSignature:
        abort(403, "Invalid Kintone OAuth cookie.")

    if (
        not provided_state
        or not hmac.compare_digest(
            provided_state,
            expected_state
        )
    ):
        abort(
            403,
            "Kintone OAuth state mismatch."
        )

    authorization_code = request.args.get("code")

    if not authorization_code:
        abort(400, "Kintone authorization declined.")

    response = requests.post(
        KINTONE + "/oauth2/token",
        auth=(K_CLIENT, K_SECRET),
        data={
            "grant_type": "authorization_code",
            "redirect_uri": BASE + "/kintone/callback",
            "code": authorization_code
        },
        timeout=15
    )

    response.raise_for_status()

    tokens = response.json()

    tokens["expires_at"] = (
        time.time() + tokens.get("expires_in", 3600)
    )

    records = kintone_records(
        tokens["access_token"],
        "employee in (LOGINUSER())"
    )

    if not records:
        return (
            "No accessible assigned movement record found. "
            "Create a record assigned to yourself first.",
            403
        )

    users = {
        record["employee"]["value"][0]["code"]
        for record in records
        if len(record["employee"]["value"]) == 1
    }

    valid_record_count = sum(
        len(record["employee"]["value"]) == 1
        for record in records
    )

    if (
        len(users) != 1
        or len(records) != valid_record_count
    ):
        return (
            "Cannot establish one Kintone employee identity.",
            403
        )

    user_code = users.pop()

    row = db.session.get(Connection, user_code)

    if row is None:

        row = Connection(
            user_code=user_code,
            kintone_tokens=encrypt(tokens)
        )

        db.session.add(row)

    else:
        row.kintone_tokens = encrypt(tokens)

    db.session.commit()

    session["user_code"] = user_code
    session.permanent = True

    result = redirect(url_for("home"))

    result.delete_cookie(
        KINTONE_STATE_COOKIE,
        path="/kintone/callback",
        secure=BASE.startswith("https://"),
        httponly=True,
        samesite="Lax"
    )

    return result


# ============================================================
# GOOGLE OAUTH CONNECT
# ============================================================

@app.route("/google/connect")
@require_login
def connect_google():

    flow = google_flow()

    state = secrets.token_urlsafe(32)

    authorization_url, returned_state = (
        flow.authorization_url(
            access_type="offline",
            prompt="consent",
            state=state
        )
    )

    oauth_data = {
        "state": returned_state,
        "verifier": flow.code_verifier,
        "user_code": session["user_code"]
    }

    response = redirect(authorization_url)

    response.set_cookie(
        GOOGLE_STATE_COOKIE,
        google_state_signer.dumps(oauth_data),
        max_age=600,
        path="/google/callback",
        secure=BASE.startswith("https://"),
        httponly=True,
        samesite="Lax"
    )

    return response


# ============================================================
# GOOGLE OAUTH CALLBACK
# ONLY ONE GOOGLE CALLBACK FUNCTION
# ============================================================

@app.route("/google/callback")
@require_login
def google_callback():

    signed_cookie = request.cookies.get(
        GOOGLE_STATE_COOKIE
    )

    if not signed_cookie:
        abort(
            403,
            "Google OAuth cookie missing. "
            "Start again from Connect Google Calendar."
        )

    try:
        oauth_data = google_state_signer.loads(
            signed_cookie,
            max_age=600
        )

    except SignatureExpired:
        abort(403, "Google OAuth authorization expired.")

    except BadSignature:
        abort(403, "Invalid Google OAuth cookie.")

    provided_state = request.args.get("state", "")
    expected_state = oauth_data.get("state", "")

    if (
        not provided_state
        or not expected_state
        or not hmac.compare_digest(
            provided_state,
            expected_state
        )
    ):
        abort(403, "Google OAuth state mismatch.")

    if oauth_data.get("user_code") != session.get("user_code"):
        abort(
            403,
            "Google OAuth employee identity mismatch."
        )

    if request.args.get("error"):
        return "Google authorization declined.", 400

    if not request.args.get("code"):
        abort(400, "Google authorization code missing.")

    flow = google_flow(state=provided_state)

    flow.code_verifier = oauth_data.get("verifier")

    # ngrok uses HTTPS externally but HTTP locally.
    # Always pass the external HTTPS URL to OAuth.

    public_callback_url = (
        BASE
        + "/google/callback?"
        + request.query_string.decode("utf-8")
    )

    flow.fetch_token(
        authorization_response=public_callback_url
    )

    credentials = flow.credentials

    service = build(
        "calendar",
        "v3",
        credentials=credentials,
        cache_discovery=False
    )


    row = stored()

    existing_tokens = (
        decrypt(row.google_tokens)
        if row.google_tokens
        else {}
    )

    token_data = json.loads(
        credentials.to_json()
    )

    if not token_data.get("refresh_token"):
        token_data["refresh_token"] = (
            existing_tokens.get("refresh_token")
        )

    if not token_data.get("refresh_token"):
        return (
            "Google did not provide a refresh token. "
            "Reconnect and grant consent.",
            400
        )

    row.google_tokens = encrypt(token_data)

    db.session.commit()

    response = redirect(url_for("home"))

    response.delete_cookie(
        GOOGLE_STATE_COOKIE,
        path="/google/callback",
        secure=BASE.startswith("https://"),
        httponly=True,
        samesite="Lax"
    )

    return response


# ============================================================
# DASHBOARD
# ============================================================

PAGE = """
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Daikai Calendar Sync Pilot</title>

<style>
body {
    font: 15px Arial, sans-serif;
    max-width: 1100px;
    margin: 32px auto;
    padding: 0 16px;
}
button, a.button {
    padding: 9px 14px;
    margin: 5px;
    display: inline-block;
}
table {
    border-collapse: collapse;
    width: 100%;
}
td, th {
    border: 1px solid #ccc;
    padding: 7px;
    text-align: left;
}
th {
    background: #f5f5f5;
}
</style>
</head>

<body>

<h2>Daikai Calendar Sync — Pilot</h2>

<p>
Verified Kintone employee:
<b>{{ user }}</b>
</p>

<p>
Google Calendar:
<b>{{ 'Connected' if connected else 'Not connected' }}</b>
</p>

{% if not connected %}

<a class="button" href="{{ url_for('connect_google') }}">
Connect Google Calendar
</a>

{% else %}

<a class="button" href="{{ url_for('preview') }}">
Preview Sync (All Months)
</a>

<form method="post" action="{{ url_for('disconnect') }}">
<input type="hidden" name="csrf" value="{{ csrf }}">
<button>Disconnect Google</button>
</form>

{% endif %}

<p>
<a href="{{ url_for('login_kintone') }}">
Switch Kintone employee / Sign in again
</a>
</p>

<p>
<small>
Manual pilot: no automated syncing.
Only events tagged by this integration are eligible for deletion.
</small>
</p>

</body>
</html>
"""


@app.route("/")
@require_login
def home():

    row = stored()

    return render_template_string(
        PAGE,
        user=session["user_code"],
        connected=row.google_tokens is not None,
        csrf=csrf()
    )


# ============================================================
# CONVERT KINTONE ROW TO GOOGLE EVENT
# ============================================================

def schedule_timezone(value, row_id):

    if value is None or (isinstance(value, str) and not value.strip()):
        name = "Asia/Singapore"
    else:
        matches = re.findall(r"\[([^\[\]]+)\]", value) if isinstance(value, str) else []

        if len(matches) != 1:
            raise ValueError(
                f"Invalid row_timezone_select in subtable row {row_id}: "
                "expected one bracketed IANA timezone."
            )

        name = matches[0]

    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError) as error:
        raise ValueError(
            f"Invalid or unavailable IANA timezone {name!r} "
            f"in subtable row {row_id}. Check the selection and installed tzdata."
        ) from error


def schedule_datetime(date_value, time_value, zone, row_id):

    try:
        local = datetime.strptime(
            date_value + " " + time_value[:5],
            "%Y-%m-%d %H:%M"
        )
    except (TypeError, ValueError) as error:
        raise ValueError(
            f"Invalid schedule date/time in subtable row {row_id}: "
            f"{date_value!r} {time_value!r}."
        ) from error

    # ZoneInfo permits gaps and folds on construction. Only accept wall times
    # that round-trip through UTC, and reject two distinct valid UTC offsets.
    candidates = {}
    for fold in (0, 1):
        candidate = local.replace(tzinfo=zone, fold=fold)
        restored = candidate.astimezone(timezone.utc).astimezone(zone)
        if restored.replace(tzinfo=None) == local:
            candidates[candidate.utcoffset()] = candidate

    if len(candidates) != 1:
        reason = "Nonexistent" if not candidates else "Ambiguous"
        raise ValueError(
            f"{reason} local time {local.isoformat()} in {zone.key} "
            f"in subtable row {row_id}. Choose a time outside the DST transition."
        )

    return next(iter(candidates.values()))


def row_event(record, subrow, user):

    values = subrow["value"]

    def field_value(name):
        return values.get(
            name, {}
        ).get("value", "")

    activity_type = field_value("row_type")

    if field_value("row_status") == "Cancelled":
        return None

    if activity_type not in (
        "Customer visit",
        "Maker visit",
        "Business trip"
    ):
        return None

    raw = [
        field_value("row_from"),
        field_value("row_to"),
        field_value("row_start_time"),
        field_value("row_end_time")
    ]

    if not all(raw):
        raise ValueError(
            "Incomplete times in subtable row "
            + str(subrow["id"])
        )

    zone = schedule_timezone(
        field_value("row_timezone_select"), subrow["id"]
    )

    start = schedule_datetime(raw[0], raw[2], zone, subrow["id"])
    end = schedule_datetime(raw[1], raw[3], zone, subrow["id"])

    if end.astimezone(timezone.utc) <= start.astimezone(timezone.utc):
        raise ValueError(
            "End <= start in subtable row "
            + str(subrow["id"])
        )

    record_id = record["$id"]["value"]

    event_key = (
        f"{APP_ID}:{record_id}:{subrow['id']}"
    )

    return {
        "summary": (
            activity_type + " - "
            + (field_value("row_place") or "Visit")
        ),
        "description": (
            "Synced from Kintone\n"
            f"Movement Record ID: {record_id}\n"
            f"Schedule Row ID: {subrow['id']}\n"
            f"Source: {KINTONE}/k/{APP_ID}/show#record={record_id}"
        ),
        "start": {
            "dateTime": start.isoformat(),
            "timeZone": zone.key
        },
        "end": {
            "dateTime": end.isoformat(),
            "timeZone": zone.key
        },
        "extendedProperties": {
            "private": {
                "kintoneKey": event_key,
                SCOPE_TAG: user
            }
        }
    }


# ============================================================
# GET EXISTING GOOGLE EVENTS
# ============================================================

def google_events(service, property_filter):

    results = []
    page_token = None

    while True:

        data = service.events().list(
            calendarId="primary",
            privateExtendedProperty=property_filter,
            showDeleted=False,
            maxResults=250,
            pageToken=page_token
        ).execute()

        results.extend(
            data.get("items", [])
        )

        page_token = data.get(
            "nextPageToken"
        )

        if not page_token:
            return results


def equal_event(current, desired):

    def moment(value):
        return datetime.fromisoformat(
            value["dateTime"].replace(
                "Z", "+00:00"
            )
        )

    return (
        current.get("summary", "") == desired["summary"]
        and current.get("description", "") == desired["description"]
        and moment(current["start"]) == moment(desired["start"])
        and moment(current["end"]) == moment(desired["end"])
    )


# ============================================================
# BUILD SYNC PLAN
# ============================================================

def build_plan(row, service):

    records = get_self_records(row)

    if not records:
        raise ValueError(
            "No accessible employee records. Deletion blocked."
        )

    desired = {}

    for record in records:

        for subrow in record["schedule"]["value"]:

            event = row_event(
                record,
                subrow,
                row.user_code
            )

            if event is None:
                continue

            event_key = (
                event["extendedProperties"]
                ["private"]["kintoneKey"]
            )

            if event_key in desired:
                raise ValueError(
                    "Duplicate row ID"
                )

            desired[event_key] = event

    existing = {}

    for event in google_events(
        service,
        SCOPE_TAG + "=" + row.user_code
    ):

        private = event.get(
            "extendedProperties", {}
        ).get("private", {})

        event_key = private.get(
            "kintoneKey"
        )

        if not event_key or event_key in existing:
            raise ValueError(
                "Duplicate or invalid Google sync metadata"
            )

        existing[event_key] = event

    # Recognize legacy events from the earlier POC.

    for event_key in desired:

        if event_key in existing:
            continue

        legacy = google_events(
            service,
            "kintoneKey=" + event_key
        )

        if len(legacy) > 1:
            raise ValueError(
                "Duplicate legacy events"
            )

        if legacy:

            private = legacy[0].get(
                "extendedProperties", {}
            ).get("private", {})

            if private.get(SCOPE_TAG) not in (
                None,
                row.user_code
            ):
                raise ValueError(
                    "Event belongs to another account"
                )

            existing[event_key] = legacy[0]

    actions = []

    for event_key, desired_event in desired.items():

        current = existing.get(event_key)

        if current is None:

            action = "CREATE"

        elif (
            equal_event(current, desired_event)
            and current.get(
                "extendedProperties", {}
            ).get("private", {}).get(SCOPE_TAG)
            == row.user_code
        ):

            action = "UNCHANGED"

        else:

            action = "UPDATE"

        actions.append({
            "action": action,
            "key": event_key,
            "title": desired_event["summary"],
            "eventId": current["id"] if current else None,
            "body": desired_event
        })

    for event_key, current in existing.items():

        private = current.get(
            "extendedProperties", {}
        ).get("private", {})

        if (
            event_key not in desired
            and private.get(SCOPE_TAG) == row.user_code
        ):

            actions.append({
                "action": "DELETE",
                "key": event_key,
                "title": current.get("summary", ""),
                "eventId": current["id"],
                "body": None
            })

    actions.sort(
        key=lambda action: action["key"]
    )

    fingerprint = hashlib.sha256(
        json.dumps(
            actions,
            sort_keys=True
        ).encode()
    ).hexdigest()

    return actions, fingerprint, len(records)


# ============================================================
# SYNC PREVIEW PAGE
# ============================================================

PREVIEW = """
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Calendar Sync Preview</title>
</head>

<body>

<h2>All-month sync preview — {{ user }}</h2>

<p>
Kintone records: {{ records }}.
No changes have been made.
</p>

<p>
CREATE {{ counts.CREATE }} |
UPDATE {{ counts.UPDATE }} |
UNCHANGED {{ counts.UNCHANGED }} |
DELETE {{ counts.DELETE }}
</p>

<p><b>Review DELETE operations before proceeding.</b></p>

<table border="1" cellpadding="6">
<tr>
<th>Action</th>
<th>Event</th>
<th>Key</th>
</tr>

{% for action in actions %}
<tr>
<td>{{ action.action }}</td>
<td>{{ action.title }}</td>
<td>{{ action.key }}</td>
</tr>
{% endfor %}

</table>

<form method="post" action="{{ url_for('apply') }}">
<input type="hidden" name="csrf" value="{{ csrf }}">
<input type="hidden" name="fingerprint" value="{{ fingerprint }}">
<button>Confirm sync</button>
</form>

<p><a href="/">Back</a></p>

</body>
</html>
"""


# ============================================================
# PREVIEW SYNC
# ============================================================

@app.route("/sync/preview")
@require_login
def preview():

    row = stored()
    service = google_service(row)

    if service is None:
        return redirect(url_for("home"))

    try:
        actions, fingerprint, record_count = build_plan(
            row, service
        )

    except (ValueError, requests.RequestException) as error:
        return (
            "Preview stopped safely: "
            + type(error).__name__
            + ": "
            + str(error),
            502
        )

    session["fingerprint"] = fingerprint
    session["preview_at"] = time.time()

    counts = {
        action_type: sum(
            action["action"] == action_type
            for action in actions
        )
        for action_type in (
            "CREATE",
            "UPDATE",
            "UNCHANGED",
            "DELETE"
        )
    }

    return render_template_string(
        PREVIEW,
        actions=actions,
        counts=counts,
        records=record_count,
        user=row.user_code,
        fingerprint=fingerprint,
        csrf=csrf()
    )


# ============================================================
# APPLY SYNC
# ============================================================

@app.route("/sync/apply", methods=["POST"])
@require_login
def apply():

    check_csrf()

    if time.time() - session.get("preview_at", 0) > 300:
        abort(409, "Preview expired.")

    row = stored()
    service = google_service(row)

    if service is None:
        abort(403)

    try:
        actions, fingerprint, _ = build_plan(row, service)

        if (
            not session.get("fingerprint")
            or not hmac.compare_digest(
                fingerprint,
                session["fingerprint"]
            )
            or not hmac.compare_digest(
                fingerprint,
                request.form.get("fingerprint", "")
            )
        ):
            abort(
                409,
                "Preview changed. Refresh before syncing."
            )

        session.pop("fingerprint", None)
        session.pop("preview_at", None)

        counts = {
            action_type: 0
            for action_type in (
                "CREATE",
                "UPDATE",
                "DELETE",
                "UNCHANGED"
            )
        }

        for action in actions:

            operation = action["action"]

            if operation == "CREATE":

                service.events().insert(
                    calendarId="primary",
                    body=action["body"],
                    sendUpdates="none"
                ).execute()

            elif operation == "UPDATE":

                service.events().patch(
                    calendarId="primary",
                    eventId=action["eventId"],
                    body=action["body"],
                    sendUpdates="none"
                ).execute()

            elif operation == "DELETE":

                service.events().delete(
                    calendarId="primary",
                    eventId=action["eventId"],
                    sendUpdates="none"
                ).execute()

            counts[operation] += 1

        return render_template_string(
            """
            <h2>Sync finished</h2>
            <p>{{ counts }}</p>
            <a href="/sync/preview">Review again</a>
            """,
            counts=counts
        )

    except (ValueError, requests.RequestException) as error:
        return (
            "Sync stopped: "
            + type(error).__name__
            + ": "
            + str(error),
            502
        )


# ============================================================
# DISCONNECT GOOGLE
# ============================================================

@app.route("/google/disconnect", methods=["POST"])
@require_login
def disconnect():

    check_csrf()

    row = stored()

    if row.google_tokens:

        token_data = decrypt(row.google_tokens)

        revoke_token = (
            token_data.get("refresh_token")
            or token_data.get("token")
        )

        if revoke_token:

            try:
                response = requests.post(
                    "https://oauth2.googleapis.com/revoke",
                    data={"token": revoke_token},
                    timeout=15
                )

                if response.status_code not in (200, 400):
                    response.raise_for_status()

            except requests.RequestException:
                return (
                    "Google revoke request failed. "
                    "Retry disconnect before removing connection.",
                    502
                )

    row.google_tokens = None
    db.session.commit()

    return redirect(url_for("home"))


# ============================================================
# HEALTH CHECK
# ============================================================

@app.route("/health")
def health():
    return {"status": "ok"}


# ============================================================
# START SERVER
# ============================================================

if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=8080,
        debug=False,
        use_reloader=False
    )
