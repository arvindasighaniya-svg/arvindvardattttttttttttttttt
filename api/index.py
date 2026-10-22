from flask import (
    Flask,
    render_template,
    request,
    jsonify,
    redirect,
    url_for,
    session,
    Response,
    stream_with_context,
)

import smtplib
import ssl
import re
import os
import json
import urllib.request
import urllib.parse
import secrets
import time

from concurrent.futures import ThreadPoolExecutor, as_completed

from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formataddr, formatdate, make_msgid
from pathlib import Path


# =========================================================
# APP
# =========================================================

BASE_DIR = Path(__file__).resolve().parent.parent

app = Flask(
    __name__,
    template_folder=str(BASE_DIR / "templates"),
    static_folder=str(BASE_DIR / "static"),
    static_url_path="/static",
)

handler = app


# =========================================================
# EXISTING VERCEL ENV VARIABLES
# =========================================================

SESSION_SECRET = os.environ.get(
    "SESSION_SECRET", ""
).strip()

TURNSTILE_SITE_KEY = os.environ.get(
    "TURNSTILE_SITE_KEY", ""
).strip()

TURNSTILE_SECRET_KEY = os.environ.get(
    "TURNSTILE_SECRET_KEY", ""
).strip()

LOGIN_PASSWORD = os.environ.get(
    "LOGIN_PASSWORD", ""
).strip()


if not SESSION_SECRET:
    raise RuntimeError(
        "SESSION_SECRET is not configured in Vercel."
    )

if not LOGIN_PASSWORD:
    raise RuntimeError(
        "LOGIN_PASSWORD is not configured in Vercel."
    )


app.secret_key = SESSION_SECRET


app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=3600,
)


# =========================================================
# MAIL SETTINGS (INBOX DELIVERY OPTIMIZED)
# =========================================================

MAX_RECIPIENTS = 25
MAX_PARALLEL_SENDS = 2  # Safe limit to avoid Gmail rate-limit spam flag

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465
SMTP_TIMEOUT = 25

SEND_DELAY_SECONDS = 2.0  # Safe interval between parallel sends


# =========================================================
# EMAIL VALIDATION
# =========================================================

EMAIL_RE = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$"
)


def valid_email(value):
    if not isinstance(value, str):
        return False

    value = value.strip()

    if not value:
        return False

    if len(value) > 254:
        return False

    return bool(EMAIL_RE.fullmatch(value))


def normalize_email(value):
    return str(value or "").strip().lower()


def authenticated():
    return session.get("authenticated") is True


def clean_header(value, max_length=998):
    value = str(value or "")
    value = value.replace("\r", " ")
    value = value.replace("\n", " ")
    return value.strip()[:max_length]


# =========================================================
# PERSONALIZATION
# =========================================================

def personalize_template(template, recipient):
    """
    Available placeholders:

        {{hi}}
        {{hello}}
        {{thanks}}
        {{name}}
        {{email}}
        {{ref_code}}

    These are replaced ONLY when they are present
    in the user's actual template.
    """

    result = str(template or "")

    values = {
        "{{hi}}": str(
            recipient.get("hi", "")
            or ""
        ),

        "{{hello}}": str(
            recipient.get("hello", "")
            or ""
        ),

        "{{thanks}}": str(
            recipient.get("thanks", "")
            or ""
        ),

        "{{name}}": str(
            recipient.get("name", "")
            or ""
        ),

        "{{email}}": str(
            recipient.get("email", "")
            or ""
        ),

        "{{ref_code}}": str(
            recipient.get("ref_code", "")
            or ""
        ),
    }

    for placeholder, value in values.items():
        result = result.replace(
            placeholder,
            value,
        )

    return result


# =========================================================
# HTML TO PLAIN TEXT
# =========================================================

def html_to_plain_text(html):

    text = str(html or "")

    text = re.sub(
        r"<br\s*/?>",
        "\n",
        text,
        flags=re.I,
    )

    text = re.sub(
        r"</p\s*>",
        "\n\n",
        text,
        flags=re.I,
    )

    text = re.sub(
        r"</div\s*>",
        "\n",
        text,
        flags=re.I,
    )

    text = re.sub(
        r"<[^>]+>",
        "",
        text,
    )

    replacements = {
        "&nbsp;": " ",
        "&amp;": "&",
        "&lt;": "<",
        "&gt;": ">",
        "&quot;": '"',
        "&#39;": "'",
    }

    for old, new in replacements.items():
        text = text.replace(old, new)

    return text.strip()


# =========================================================
# TURNSTILE
# =========================================================

def verify_turnstile(token, remote_ip=None):

    if not TURNSTILE_SECRET_KEY:
        return (
            False,
            "TURNSTILE_SECRET_KEY is not configured.",
        )

    if not token:
        return (
            False,
            "Cloudflare verification is required.",
        )

    payload = {
        "secret": TURNSTILE_SECRET_KEY,
        "response": token,
    }

    if remote_ip:
        payload["remoteip"] = remote_ip

    encoded = urllib.parse.urlencode(
        payload
    ).encode("utf-8")

    req = urllib.request.Request(
        "https://challenges.cloudflare.com/turnstile/v0/siteverify",
        data=encoded,
        headers={
            "Content-Type":
                "application/x-www-form-urlencoded"
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(
            req,
            timeout=10,
        ) as response:

            result = json.loads(
                response.read().decode("utf-8")
            )

        if result.get("success") is True:
            return True, None

        return (
            False,
            "Cloudflare verification failed.",
        )

    except Exception:
        return (
            False,
            "Unable to verify Cloudflare.",
        )


# =========================================================
# LOGIN
# =========================================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if authenticated():
        return redirect(url_for("home"))

    if request.method == "GET":

        return render_template(
            "login.html",
            error=None,
            turnstile_site_key=TURNSTILE_SITE_KEY,
        )

    password = str(
        request.form.get(
            "password",
            "",
        )
    )

    if not secrets.compare_digest(
        password,
        LOGIN_PASSWORD,
    ):

        return render_template(
            "login.html",
            error="Incorrect password.",
            turnstile_site_key=TURNSTILE_SITE_KEY,
        ), 401

    session.clear()
    session.permanent = True
    session["authenticated"] = True

    return redirect(url_for("home"))


# =========================================================
# LOGOUT
# =========================================================

@app.route(
    "/logout",
    methods=["GET", "POST"],
)
def logout():

    session.clear()

    return redirect(
        url_for("login")
    )


# =========================================================
# HOME
# =========================================================

@app.route("/")
def home():

    if not authenticated():
        return redirect(
            url_for("login")
        )

    return render_template(
        "index.html",
        turnstile_site_key=TURNSTILE_SITE_KEY,
    )


# =========================================================
# BUILD EMAIL (INBOX DELIVERABILITY FIXED)
# =========================================================

def build_message(
    gmail,
    sender_name,
    subject,
    body,
    is_html,
    recipient,
):

    gmail = gmail.strip().lower()
    recipient = recipient.strip()

    sender_name = clean_header(
        sender_name,
        200,
    )

    subject = clean_header(
        subject,
        998,
    )

    body = str(
        body or ""
    ).replace(
        "\x00",
        "",
    )

    if is_html:

        message = MIMEMultipart(
            "alternative"
        )

        plain_body = html_to_plain_text(
            body
        )

        # RFC 2046 Compliance: Plain text part first, HTML part second
        message.attach(
            MIMEText(
                plain_body,
                "plain",
                "utf-8",
            )
        )

        message.attach(
            MIMEText(
                body,
                "html",
                "utf-8",
            )
        )

    else:

        message = MIMEText(
            body,
            "plain",
            "utf-8",
        )

    message["Subject"] = subject

    message["From"] = formataddr(
        (
            sender_name,
            gmail,
        )
    )

    message["To"] = recipient

    message["Reply-To"] = formataddr(
        (
            sender_name,
            gmail,
        )
    )

    message["Date"] = formatdate(
        localtime=True
    )

    # Valid Domain Message-ID Fix (Avoids bot spam filter)
    domain_part = gmail.split("@")[1] if "@" in gmail else "gmail.com"
    message["Message-ID"] = make_msgid(
        domain=domain_part
    )

    # Anti-Spam Headers
    message["MIME-Version"] = "1.0"
    message["X-Mailer"] = "Python-SMTP-Console"
    message["X-Priority"] = "3"

    return message


# =========================================================
# NORMALIZE RECIPIENT
# =========================================================

def normalize_recipient(item):

    # Simple email:
    #
    # "user@example.com"

    if isinstance(item, str):

        return {
            "email": normalize_email(item),
            "name": "",
            "hi": "",
            "hello": "",
            "thanks": "",
            "ref_code": "",
        }

    # Detailed recipient:
    #
    # {
    #    "email": "...",
    #    "name": "...",
    #    "hi": "Hi",
    #    "hello": "Hello",
    #    "thanks": "Thanks",
    #    "ref_code": "HF8552"
    # }

    if not isinstance(item, dict):
        return None

    email = normalize_email(
        item.get("email", "")
    )

    name = str(
        item.get("name", "")
        or ""
    ).strip()

    hi = str(
        item.get("hi", "")
        or ""
    ).strip()

    hello = str(
        item.get("hello", "")
        or ""
    ).strip()

    thanks = str(
        item.get("thanks", "")
        or ""
    ).strip()

    ref_code = str(
        item.get("ref_code", "")
        or ""
    ).strip()

    # Clean values that might later
    # appear in mail content.

    name = (
        name
        .replace("\r", " ")
        .replace("\n", " ")
    )

    hi = (
        hi
        .replace("\r", " ")
        .replace("\n", " ")
    )

    hello = (
        hello
        .replace("\r", " ")
        .replace("\n", " ")
    )

    thanks = (
        thanks
        .replace("\r", " ")
        .replace("\n", " ")
    )

    ref_code = (
        ref_code
        .replace("\r", " ")
