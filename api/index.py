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
# APP CONFIGURATION
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
# ENVIRONMENT VARIABLES
# =========================================================

SESSION_SECRET = os.environ.get("SESSION_SECRET", "").strip()
TURNSTILE_SITE_KEY = os.environ.get("TURNSTILE_SITE_KEY", "").strip()
TURNSTILE_SECRET_KEY = os.environ.get("TURNSTILE_SECRET_KEY", "").strip()
LOGIN_PASSWORD = os.environ.get("LOGIN_PASSWORD", "").strip()

if not SESSION_SECRET:
    raise RuntimeError("SESSION_SECRET is not configured in Vercel.")

if not LOGIN_PASSWORD:
    raise RuntimeError("LOGIN_PASSWORD is not configured in Vercel.")

app.secret_key = SESSION_SECRET

app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=3600,
)


# =========================================================
# MAIL SETTINGS (OPTIMIZED FOR INBOX DELIVERY)
# =========================================================

MAX_RECIPIENTS = 25
MAX_PARALLEL_SENDS = 2  # Reduced to avoid Gmail SMTP rate-limit bans

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465
SMTP_TIMEOUT = 30

SEND_DELAY_SECONDS = 2.0  # Safe delay between threads


# =========================================================
# EMAIL VALIDATION & SANITIZATION
# =========================================================

EMAIL_RE = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$"
)


def valid_email(value):
    if not isinstance(value, str):
        return False
    value = value.strip()
    if not value or len(value) > 254:
        return False
    return bool(EMAIL_RE.fullmatch(value))


def normalize_email(value):
    return str(value or "").strip().lower()


def authenticated():
    return session.get("authenticated") is True


def clean_header(value, max_length=998):
    value = str(value or "")
    value = value.replace("\r", " ").replace("\n", " ")
    return value.strip()[:max_length]


# =========================================================
# TEMPLATE PERSONALIZATION
# =========================================================

def personalize_template(template, recipient):
    result = str(template or "")
    values = {
        "{{hi}}": str(recipient.get("hi", "") or ""),
        "{{hello}}": str(recipient.get("hello", "") or ""),
        "{{thanks}}": str(recipient.get("thanks", "") or ""),
        "{{name}}": str(recipient.get("name", "") or ""),
        "{{email}}": str(recipient.get("email", "") or ""),
        "{{ref_code}}": str(recipient.get("ref_code", "") or ""),
    }
    for placeholder, value in values.items():
        result = result.replace(placeholder, value)
    return result


# =========================================================
# HTML TO PLAIN TEXT CONVERSION (SPAM FILTER COMPLIANT)
# =========================================================

def html_to_plain_text(html):
    text = str(html or "")
    text = re.sub(r"<br\s*/?>", "\n", text, flags=re.I)
    text = re.sub(r"</p\s*>", "\n\n", text, flags=re.I)
    text = re.sub(r"</div\s*>", "\n", text, flags=re.I)
    text = re.sub(r"<[^>]+>", "", text)
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
# TURNSTILE VERIFICATION
# =========================================================

def verify_turnstile(token, remote_ip=None):
    if not TURNSTILE_SECRET_KEY:
        return False, "TURNSTILE_SECRET_KEY is not configured."
    if not token:
        return False, "Cloudflare verification is required."

    payload = {"secret": TURNSTILE_SECRET_KEY, "response": token}
    if remote_ip:
        payload["remoteip"] = remote_ip

    encoded = urllib.parse.urlencode(payload).encode("utf-8")
    req = urllib.request.Request(
        "https://challenges.cloudflare.com/turnstile/v0/siteverify",
        data=encoded,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            result = json.loads(response.read().decode("utf-8"))
        if result.get("success") is True:
            return True, None
        return False, "Cloudflare verification failed."
    except Exception:
        return False, "Unable to verify Cloudflare."


# =========================================================
# ROUTE HANDLERS
# =========================================================

@app.route("/login", methods=["GET", "POST"])
def login():
    if authenticated():
        return redirect(url_for("home"))
    if request.method == "GET":
        return render_template("login.html", error=None, turnstile_site_key=TURNSTILE_SITE_KEY)

    password = str(request.form.get("password", ""))
    if not secrets.compare_digest(password, LOGIN_PASSWORD):
        return render_template("login.html", error="Incorrect password.", turnstile_site_key=TURNSTILE_SITE_KEY), 401

    session.clear()
    session.permanent = True
    session["authenticated"] = True
    return redirect(url_for("home"))


@app.route("/logout", methods=["GET", "POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
def home():
    if not authenticated():
        return redirect(url_for("login"))
    return render_template("index.html", turnstile_site_key=TURNSTILE_SITE_KEY)


# =========================================================
# BUILD EMAIL (INBOX ENHANCED HEADERS)
# =========================================================

def build_message(gmail, sender_name, subject, body, is_html, recipient):
    gmail = gmail.strip().lower()
    recipient = recipient.strip()
    sender_name = clean_header(sender_name, 200)
    subject = clean_header(subject, 998)
    body = str(body or "").replace("\x00", "")

    if is_html:
        message = MIMEMultipart("alternative")
        plain_body = html_to_plain_text(body)
        
        # RFC 2046 Compliance: Plain Text part first, HTML part second
        message.attach(MIMEText(plain_body, "plain", "utf-8"))
        message.attach(MIMEText(body, "html", "utf-8"))
    else:
        message = MIMEText(body, "plain", "utf-8")

    message["Subject"] = subject
    message["From"] = formataddr((sender_name, gmail))
    message["To"] = recipient
    message["Reply-To"] = formataddr((sender_name, gmail))
    message["Date"] = formatdate(localtime=True)

    # Domain specific RFC Compliant Message-ID Generation
    domain_part = gmail.split("@")[1] if "@" in gmail else "gmail.com"
    message["Message-ID"] = make_msgid(domain=domain_part)

    # Standard Trust Headers
    message["MIME-Version"] = "1.0"
    message["X-Mailer"] = "Python-SMTP-Console"
    message["X-Priority"] = "3"  # Normal priority

    return message


# =========================================================
# RECIPIENT NORMALIZATION
# =========================================================

def normalize_recipient(item):
    if isinstance(item, str):
        return {
            "email": normalize_email(item),
            "name": "",
            "hi": "",
            "hello": "",
            "thanks": "",
            "ref_code": "",
        }
    if not isinstance(item, dict):
        return None

    return {
        "email": normalize_email(item.get("email", "")),
        "name": str(item.get("name", "") or "").strip().replace("\r", " ").replace("\n", " ")[:200],
        "hi": str(item.get("hi", "") or "").strip().replace("\r", " ").replace("\n", " ")[:100],
        "hello": str(item.get("hello", "") or "").strip().replace("\r", " ").replace("\n", " ")[:100],
        "thanks": str(item.get("thanks", "") or "").strip().replace("\r", " ").replace("\n", " ")[:100],
        "ref_code": str(item.get("ref_code", "") or "").strip().replace("\r", " ").replace("\n", " ")[:200],
    }


# =========================================================
# DISPATCH SINGLE MAIL WORKER
# =========================================================

def send_one_email(gmail, app_password, sender_name, subject, body, is_html, recipient_data):
    recipient = normalize_email(recipient_data.get("email", ""))
    clean_app_password = re.sub(r"\s+", "", str(app_password or ""))

    personalized_subject = personalize_template(subject, recipient_data)
    personalized_body = personalize_template(body, recipient_data)

    if SEND_DELAY_SECONDS > 0:
        time.sleep(SEND_DELAY_SECONDS)

    message = build_message(
        gmail=gmail,
        sender_name=sender_name,
        subject=personalized_subject,
        body=personalized_body,
        is_html=is_html,
        recipient=recipient,
    )

    context = ssl.create_default_context()

    try:
        with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, context=context, timeout=SMTP_TIMEOUT) as server:
            server.ehlo()
            server.login(gmail, clean_app_password)
            refused = server.sendmail(gmail, [recipient], message.as_string())

            if refused:
                return {"email": recipient, "result": "failed", "error": "SMTP refused recipient."}

        return {"email": recipient, "result": "sent"}

    except smtplib.SMTPAuthenticationError:
        return {"email": recipient, "result": "failed", "error": "Authentication failed. Check Gmail App Password."}
    except smtplib.SMTPRecipientsRefused:
        return {"email": recipient, "result": "failed", "error": "Recipient address was refused."}
    except Exception as exc:
        return {"email": recipient, "result": "failed", "error": str(exc)[:300]}


# =========================================================
# BATCH BATCH DISPATCH STREAM ROUTE
# =========================================================

@app.route("/send-batch", methods=["POST"])
def send_batch():
    if not authenticated():
        return jsonify({"success": False, "message": "Authentication required.", "login_required": True}), 401

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"success": False, "message": "Invalid JSON request."}), 400

    sender_name = clean_header(data.get("sender_name", ""), 200)
    gmail = clean_header(data.get("gmail", ""), 254)
    app_password = str(data.get("app_password", "")).strip()
    subject = clean_header(data.get("subject", ""), 998)
    body = str(data.get("body", ""))
    is_html = data.get("is_html", False) is True
    recipients = data.get("recipients", [])
    turnstile_token = str(data.get("turnstile_token", "")).strip()

    if not sender_name:
        return jsonify({"success": False, "message": "Sender Name is required."}), 400
    if not
