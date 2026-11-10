
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
from contextlib import contextmanager
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import requests

from cryptography.fernet import Fernet
from dotenv import load_dotenv
from flask import (
    Flask, request, session, redirect,
    url_for, render_template_string, abort, g
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
from google.oauth2 import id_token
from google.auth.exceptions import GoogleAuthError
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from oauthlib.oauth2 import OAuth2Error
from sqlalchemy.exc import IntegrityError


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
    "https://www.googleapis.com/auth/calendar.events",
    "openid",
    "https://www.googleapis.com/auth/userinfo.email"
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


class ConnectionSecurity(db.Model):
    # Additive migration: the existing connection table and token blobs stay intact.
    user_code = db.Column(db.String(150), primary_key=True)
    google_sub = db.Column(db.String(255), unique=True, nullable=True)
    google_label = db.Column(db.String(320), nullable=True)
    version = db.Column(db.String(64), nullable=False)
    busy = db.Column(db.String(64), nullable=True)


class BrowserSession(db.Model):
    sid_hash = db.Column(db.String(64), primary_key=True)
    user_code = db.Column(db.String(150), nullable=True)
    expires_at = db.Column(db.Float, nullable=False)
    kintone_state = db.Column(db.String(64), nullable=True)
    google_state = db.Column(db.String(64), nullable=True)


class SyncApproval(db.Model):
    token_hash = db.Column(db.String(64), primary_key=True)
    sid_hash = db.Column(db.String(64), nullable=False, index=True)
    user_code = db.Column(db.String(150), nullable=False, index=True)
    google_sub = db.Column(db.String(255), nullable=False)
    destination = db.Column(db.String(32), nullable=False)
    version = db.Column(db.String(64), nullable=False)
    fingerprint = db.Column(db.String(64), nullable=False)
    expires_at = db.Column(db.Float, nullable=False)
    consumed = db.Column(db.Boolean, nullable=False, default=False)


with app.app_context():
    # Serialize SQLite's check/create sequence when several workers start together.
    with db.engine.begin() as migration:
        if db.engine.dialect.name == "sqlite":
            migration.exec_driver_sql("BEGIN IMMEDIATE")
        db.metadata.create_all(bind=migration)


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


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def current_browser():
    sid = session.get("sid")
    if not isinstance(sid, str):
        return None
    browser = db.session.get(BrowserSession, digest(sid), populate_existing=True)
    if browser is None or browser.expires_at <= time.time():
        return None
    if browser.user_code != session.get("user_code"):
        return None
    return browser


def security_for(user_code):
    security = db.session.get(ConnectionSecurity, user_code, populate_existing=True)
    if security is None:
        security = ConnectionSecurity(user_code=user_code, version=secrets.token_hex(32))
        db.session.add(security)
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            security = db.session.get(ConnectionSecurity, user_code, populate_existing=True)
    return security


@contextmanager
def connection_guard(user_code):
    """Durable CAS lock, shared by processes; never expire a running writer's lock.

    A killed worker leaves a fail-closed lock for operator review. Transactions
    are short: no SQLite transaction is held across an external network call.
    """
    security_for(user_code)
    owner = secrets.token_hex(32)
    acquired = ConnectionSecurity.query.filter_by(user_code=user_code, busy=None).update(
        {"busy": owner}, synchronize_session=False
    )
    db.session.commit()
    if acquired != 1:
        abort(409, "This connection is busy or requires recovery. Retry after review.")
    try:
        yield security_for(user_code)
    finally:
        db.session.rollback()
        ConnectionSecurity.query.filter_by(user_code=user_code, busy=owner).update(
            {"busy": None}, synchronize_session=False
        )
        db.session.commit()


def invalidate_approvals(user_code):
    SyncApproval.query.filter_by(user_code=user_code).delete(synchronize_session=False)
    session.pop("fingerprint", None)
    session.pop("preview_at", None)


def invalidate_connection(security):
    invalidate_approvals(security.user_code)
    security.version = secrets.token_hex(32)
    BrowserSession.query.filter_by(user_code=security.user_code).update(
        {"google_state": None}, synchronize_session=False
    )
    db.session.commit()


def require_current_browser():
    browser = current_browser()
    if browser is None or not browser.user_code:
        abort(403, "Session expired or logged out. Sign in again.")
    return browser


def clear_oauth_cookies(response):
    for name, path in ((KINTONE_STATE_COOKIE, "/kintone/callback"),
                       (GOOGLE_STATE_COOKIE, "/google/callback")):
        response.delete_cookie(name, path=path, secure=BASE.startswith("https://"),
                               httponly=True, samesite="Lax")
    return response


def plain_error(message, status=502):
    return app.response_class(message, status=status, mimetype="text/plain")


@app.errorhandler(ValueError)
def validation_error(error):
    return plain_error("Operation stopped safely: " + str(error), 400)


def external_error(error):
    return plain_error("External authorization or API request failed. Refresh and review before retrying.")


for external_error_type in (requests.RequestException, GoogleAuthError, HttpError, OAuth2Error):
    app.register_error_handler(external_error_type, external_error)


@app.after_request
def private_responses(response):
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


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

        browser = current_browser()
        if browser is None or not browser.user_code:
            session.clear()
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


def locked_connection(function):
    @wraps(function)
    def inner(*args, **kwargs):
        with connection_guard(session["user_code"]) as security:
            require_current_browser()
            g.connection_security = security
            return function(*args, **kwargs)
    return inner


def consume_oauth_state(kind, expected):
    browser = current_browser()
    if browser is None:
        abort(403, "OAuth session expired or logged out.")
    field = getattr(BrowserSession, kind + "_state")
    changed = BrowserSession.query.filter(
        BrowserSession.sid_hash == browser.sid_hash,
        BrowserSession.expires_at > time.time(), field == digest(expected)
    ).update({field: None}, synchronize_session=False)
    db.session.commit()
    if changed != 1:
        abort(403, "OAuth state expired, superseded, or already used.")


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

def google_client():
    return json.loads(GOOGLE_JSON.read_text(encoding="utf-8"))["web"]


def google_credentials(token_data):
    client = google_client()
    return Credentials.from_authorized_user_info(
        dict(token_data, token_uri="https://oauth2.googleapis.com/token",
             client_id=client["client_id"], client_secret=client["client_secret"]),
        scopes=token_data.get("scopes") or [GOOGLE_SCOPE[0]]
    )


def access_identity(credentials):
    """Verify the access token's subject using Google's supported UserInfo API."""
    try:
        response = requests.get(
            "https://openidconnect.googleapis.com/v1/userinfo",
            headers={"Authorization": "Bearer " + credentials.token}, timeout=15
        )
        response.raise_for_status()
        profile = response.json()
        if not isinstance(profile.get("sub"), str) or not profile["sub"]:
            raise ValueError("Missing subject")
        return profile
    except (requests.RequestException, ValueError, TypeError) as error:
        raise ValueError("Google account verification failed. Existing connection preserved.") from error


def legacy_subject(token_data):
    """One-time, fail-closed upgrade of calendar-only credentials.

    Refresh independently, then use Google's token introspection API. Some old
    grants may not expose a subject: never infer one from event content/email.
    """
    try:
        credentials = google_credentials(token_data)
        credentials.refresh(Request())
        response = requests.get(
            "https://oauth2.googleapis.com/tokeninfo",
            params={"access_token": credentials.token}, timeout=15
        )
        response.raise_for_status()
        info = response.json()
        subject = info.get("sub")
        if (not isinstance(subject, str) or not subject
                or info.get("aud") != google_client()["client_id"]
                or int(info.get("expires_in", 0)) <= 0):
            raise ValueError("Unverifiable legacy identity")
        return subject
    except (GoogleAuthError, requests.RequestException, ValueError, TypeError) as error:
        # Never expose tokeninfo request URLs, which contain a bearer token.
        raise ValueError(
            "Legacy Google account could not be verified. Tokens are unchanged; "
            "operator-assisted identity verification is required before reconnect."
        ) from error


def verified_google_tokens(credentials, nonce, previous, security):
    """Return a fully verified token set without mutating persistent state."""
    try:
        if (credentials.granted_scopes is not None
                and GOOGLE_SCOPE[0] not in credentials.granted_scopes):
            raise ValueError("Calendar permission was not granted")
        claims = id_token.verify_oauth2_token(
            credentials.id_token, Request(), google_client()["client_id"]
        )
        if (not nonce or claims.get("nonce") != nonce
                or claims.get("azp", google_client()["client_id"]) != google_client()["client_id"]):
            raise ValueError("Invalid nonce or authorized party")
        profile = access_identity(credentials)
        subject = profile["sub"]
        if claims.get("sub") != subject:
            raise ValueError("Access and ID token subjects differ")
    except (GoogleAuthError, requests.RequestException, ValueError, TypeError) as error:
        raise ValueError("Google identity verification failed. Existing connection preserved.") from error

    expected = security.google_sub
    if previous and expected is None:
        expected = legacy_subject(previous)
    if expected is not None and expected != subject:
        raise ValueError("Google account switching is blocked. Select the previously linked account.")
    other = ConnectionSecurity.query.filter(
        ConnectionSecurity.google_sub == subject,
        ConnectionSecurity.user_code != security.user_code
    ).first()
    if other is not None:
        raise ValueError("This Google account is already linked to another employee.")
    unverified_other = db.session.query(Connection.user_code).outerjoin(
        ConnectionSecurity, ConnectionSecurity.user_code == Connection.user_code
    ).filter(
        Connection.user_code != security.user_code, Connection.google_tokens.isnot(None),
        ConnectionSecurity.google_sub.is_(None)
    ).first()
    if unverified_other is not None:
        raise ValueError("Another employee has an unverified legacy Google connection. Verify it first.")

    tokens = json.loads(credentials.to_json())
    if not tokens.get("refresh_token"):
        # Legacy grants need fresh consent: only already verified grants can reuse.
        if security.google_sub == subject and previous.get("refresh_token"):
            tokens["refresh_token"] = previous["refresh_token"]
        else:
            raise ValueError("Google did not provide a safe refresh token. Reconnect with consent.")

    # Verify the refresh token independently, even for newly returned token sets.
    try:
        refreshed = google_credentials(tokens)
        refreshed.refresh(Request())
        if (refreshed.granted_scopes is not None
                and GOOGLE_SCOPE[0] not in refreshed.granted_scopes):
            raise ValueError("Refresh token lacks Calendar permission")
        if access_identity(refreshed)["sub"] != subject:
            raise ValueError("Refresh token subject mismatch")
    except (GoogleAuthError, requests.RequestException, ValueError, TypeError) as error:
        raise ValueError("Refresh token ownership could not be verified. Connection unchanged.") from error

    tokens = json.loads(refreshed.to_json())
    label = (profile.get("email") if profile.get("email_verified") is True else None)
    return tokens, subject, label or ("Google account " + subject)


def google_service(row):

    if row is None or row.google_tokens is None:
        return None

    security = security_for(row.user_code)
    if not security.google_sub:
        raise ValueError("Legacy Google connection needs verified reconnect before preview or sync.")
    token_data = decrypt(row.google_tokens)
    credentials = google_credentials(token_data)

    if not credentials.valid:

        credentials.refresh(Request())

        if access_identity(credentials)["sub"] != security.google_sub:
            raise ValueError("Google refresh account mismatch. Sync blocked.")
        row.google_tokens = encrypt(json.loads(credentials.to_json()))
        db.session.commit()

    elif access_identity(credentials)["sub"] != security.google_sub:
        raise ValueError("Google account mismatch. Sync blocked.")

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

    old_browser = current_browser()
    if old_browser is not None:
        if old_browser.user_code:
            with connection_guard(old_browser.user_code):
                invalidate_approvals(old_browser.user_code)
                db.session.delete(old_browser)
                db.session.commit()
        else:
            db.session.delete(old_browser)
            db.session.commit()
    session.clear()

    state = secrets.token_urlsafe(28)
    sid = secrets.token_urlsafe(32)
    session["sid"] = sid
    session.permanent = True
    db.session.add(BrowserSession(
        sid_hash=digest(sid), user_code=None, expires_at=time.time() + 600,
        kintone_state=digest(state)
    ))
    db.session.commit()

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

    response.delete_cookie(GOOGLE_STATE_COOKIE, path="/google/callback",
                           secure=BASE.startswith("https://"), httponly=True, samesite="Lax")
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

    consume_oauth_state("kintone", expected_state)
    pending_sid = digest(session["sid"])

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

    with connection_guard(user_code):
        pending = current_browser()
        if pending is None or pending.sid_hash != pending_sid:
            abort(403, "Login session expired. Start again.")
        row = db.session.get(Connection, user_code)
        if row is None:
            row = Connection(user_code=user_code, kintone_tokens=encrypt(tokens))
            db.session.add(row)
        else:
            row.kintone_tokens = encrypt(tokens)
        invalidate_approvals(user_code)
        db.session.delete(pending)
        session.clear()
        sid = secrets.token_urlsafe(32)
        session.update(sid=sid, user_code=user_code)
        session.permanent = True
        db.session.add(BrowserSession(
            sid_hash=digest(sid), user_code=user_code, expires_at=time.time() + 8 * 3600
        ))
        db.session.commit()

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
@locked_connection
def connect_google():

    invalidate_connection(g.connection_security)
    flow = google_flow()

    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)

    authorization_url, returned_state = (
        flow.authorization_url(
            access_type="offline",
            prompt="consent select_account",
            state=state,
            nonce=nonce
        )
    )

    oauth_data = {
        "state": returned_state,
        "verifier": flow.code_verifier,
        "user_code": session["user_code"],
        "nonce": nonce,
        "version": g.connection_security.version,
        "sid_hash": digest(session["sid"])
    }
    browser = require_current_browser()
    browser.google_state = digest(returned_state)
    db.session.commit()

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
@locked_connection
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

    if (oauth_data.get("sid_hash") != digest(session["sid"])
            or oauth_data.get("version") != g.connection_security.version):
        abort(403, "OAuth connection or session changed. Start again.")
    consume_oauth_state("google", expected_state)

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

    row = stored()
    existing_tokens = (
        decrypt(row.google_tokens)
        if row.google_tokens
        else {}
    )

    token_data, subject, label = verified_google_tokens(
        flow.credentials, oauth_data.get("nonce"), existing_tokens, g.connection_security
    )
    require_current_browser()
    g.connection_security.google_sub = subject
    g.connection_security.google_label = label
    row.google_tokens = encrypt(token_data)
    try:
        invalidate_connection(g.connection_security)
    except IntegrityError:
        db.session.rollback()
        return plain_error("Google account is already linked. Existing connection preserved.", 409)

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
{% if connected %}
<p>Google account: <b>{{ google_label or 'Legacy connection — verified reconnect required' }}</b>.
Destination: primary calendar.</p>
<a class="button" href="{{ url_for('connect_google') }}">Verify / reconnect same Google account</a>
{% endif %}

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
<form method="post" action="{{ url_for('logout') }}">
<input type="hidden" name="csrf" value="{{ csrf }}">
<button>Log out</button>
</form>

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
        google_label=security_for(row.user_code).google_label,
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
    visible_records = {str(record["$id"]["value"]) for record in records}

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

        if private.get(SCOPE_TAG) != row.user_code:
            continue

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
            parts = event_key.split(":")
            parent_visible = (len(parts) == 3 and parts[0] == str(APP_ID)
                              and parts[1] in visible_records)
            actions.append({
                "action": "DELETE" if parent_visible else "BLOCKED",
                "key": event_key,
                "title": current.get("summary", ""),
                "eventId": current["id"],
                "body": None,
                "reason": "" if parent_visible else "Parent record is not visible; deletion requires review."
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
| BLOCKED {{ counts.BLOCKED }}
</p>
<p>Google account: {{ google_label }}. Destination: primary calendar.</p>
{% if counts.BLOCKED %}<p>Missing parent records require review. No sync can be confirmed.</p>{% endif %}

<p><b>Review DELETE operations before proceeding.</b></p>

<table border="1" cellpadding="6">
<tr>
<th>Action</th>
<th>Event</th>
<th>Key</th>
<th>Review</th>
</tr>

{% for action in actions %}
<tr>
<td>{{ action.action }}</td>
<td>{{ action.title }}</td>
<td>{{ action.key }}</td>
<td>{{ action.reason|default('') }}</td>
</tr>
{% endfor %}

</table>

{% if not counts.BLOCKED %}
<form method="post" action="{{ url_for('apply') }}">
<input type="hidden" name="csrf" value="{{ csrf }}">
<input type="hidden" name="fingerprint" value="{{ fingerprint }}">
<input type="hidden" name="approval" value="{{ approval }}">
<button>Confirm sync</button>
</form>
{% endif %}

<p><a href="/">Back</a></p>

</body>
</html>
"""


# ============================================================
# PREVIEW SYNC
# ============================================================

@app.route("/sync/preview")
@require_login
@locked_connection
def preview():

    browser = require_current_browser()
    SyncApproval.query.filter_by(sid_hash=browser.sid_hash).delete(synchronize_session=False)
    db.session.commit()
    row = stored()

    try:
        service = google_service(row)
        if service is None:
            return redirect(url_for("home"))
        actions, fingerprint, record_count = build_plan(
            row, service
        )

    except ValueError as error:
        return plain_error("Preview stopped safely: ValueError: " + str(error))

    approval = secrets.token_urlsafe(32)
    if not any(action["action"] == "BLOCKED" for action in actions):
        db.session.add(SyncApproval(
            token_hash=digest(approval), sid_hash=browser.sid_hash, user_code=row.user_code,
            google_sub=g.connection_security.google_sub, destination="primary",
            version=g.connection_security.version, fingerprint=fingerprint,
            expires_at=time.time() + 300
        ))
        db.session.commit()

    counts = {
        action_type: sum(
            action["action"] == action_type
            for action in actions
        )
        for action_type in (
            "CREATE",
            "UPDATE",
            "UNCHANGED",
            "DELETE",
            "BLOCKED"
        )
    }

    return render_template_string(
        PREVIEW,
        actions=actions,
        counts=counts,
        records=record_count,
        user=row.user_code,
        fingerprint=fingerprint,
        approval=approval,
        google_label=g.connection_security.google_label,
        csrf=csrf()
    )


# ============================================================
# APPLY SYNC
# ============================================================

def deterministic_event_id(user_code, event_key):
    # Hex is a valid subset of Calendar's base32hex ID alphabet.
    return "d" + digest(json.dumps([KINTONE, user_code, event_key]))


def create_event(service, action, user_code):
    event_id = deterministic_event_id(user_code, action["key"])
    body = dict(action["body"], id=event_id)
    try:
        service.events().insert(calendarId="primary", body=body, sendUpdates="none").execute()
    except HttpError as error:
        if error.resp.status != 409:
            raise
        # A retry after a timeout must never allocate a second ID or overwrite
        # a colliding/changed event. A tombstone also fails closed here.
        current = service.events().get(calendarId="primary", eventId=event_id).execute()
        private = current.get("extendedProperties", {}).get("private", {})
        if (current.get("status") == "cancelled"
                or private.get(SCOPE_TAG) != user_code
                or private.get("kintoneKey") != action["key"]
                or not equal_event(current, action["body"])):
            abort(409, "Existing event differs or was deleted. Refresh preview and review.")


def consume_approval(browser, security, token, fingerprint):
    changed = SyncApproval.query.filter_by(
        token_hash=digest(token), sid_hash=browser.sid_hash, user_code=browser.user_code,
        google_sub=security.google_sub, destination="primary", version=security.version,
        fingerprint=fingerprint, consumed=False
    ).filter(SyncApproval.expires_at > time.time()).update(
        {"consumed": True}, synchronize_session=False
    )
    db.session.commit()
    if changed != 1:
        abort(409, "Approval expired, already used, or destination/session changed. Refresh preview.")


@app.route("/sync/apply", methods=["POST"])
@require_login
@locked_connection
def apply():

    check_csrf()

    browser = require_current_browser()
    fingerprint = request.form.get("fingerprint", "")
    consume_approval(browser, g.connection_security, request.form.get("approval", ""), fingerprint)

    row = stored()
    service = google_service(row)

    if service is None:
        abort(403)

    try:
        actions, rebuilt_fingerprint, _ = build_plan(row, service)
        if (not hmac.compare_digest(fingerprint, rebuilt_fingerprint)
                or any(action["action"] == "BLOCKED" for action in actions)):
            abort(
                409,
                "Preview changed. Refresh before syncing."
            )

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

                create_event(service, action, row.user_code)

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

    except ValueError as error:
        return plain_error("Sync stopped safely: " + str(error))


# ============================================================
# DISCONNECT GOOGLE
# ============================================================

@app.route("/google/disconnect", methods=["POST"])
@require_login
@locked_connection
def disconnect():

    check_csrf()
    invalidate_connection(g.connection_security)

    row = stored()

    if row.google_tokens:

        token_data = decrypt(row.google_tokens)
        if g.connection_security.google_sub is None:
            # Retain a verified binding even after disconnect; do not discard
            # the only evidence of the old account and silently allow a swap.
            g.connection_security.google_sub = legacy_subject(token_data)
            g.connection_security.google_label = "Google account " + g.connection_security.google_sub
            try:
                db.session.commit()
            except IntegrityError:
                db.session.rollback()
                return plain_error("Account ownership conflict. Existing connection preserved.", 409)

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
# LOGOUT
# ============================================================

@app.route("/logout", methods=["POST"])
@require_login
@locked_connection
def logout():
    check_csrf()
    browser = require_current_browser()
    invalidate_approvals(browser.user_code)
    db.session.delete(browser)
    db.session.commit()
    session.clear()
    return clear_oauth_cookies(plain_error("Logged out. Sign in again at /login.", 200))


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
