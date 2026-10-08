import os
import json
import re
import smtplib
import ssl
import urllib.request
import urllib.parse
import secrets
import random
import time
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formataddr, formatdate, make_msgid 
from pathlib import Path
from flask import (
    Flask, render_template, request, jsonify,
    redirect, url_for, session, Response,
    stream_with_context
)

BASE_DIR = Path(__file__).resolve().parent.parent

app = Flask(
    __name__,
    template_folder=str(BASE_DIR / "templates"),
    static_folder=str(BASE_DIR / "static"),
    static_url_path="/static"
)

app.secret_key = (
    os.environ.get("SESSION_SECRET")
    or os.environ.get("FLASK_SECRET_KEY")
    or secrets.token_hex(32)
)

MAX_RECIPIENTS = 500  # Flexible limit for batching

TURNSTILE_SECRET_KEY = os.environ.get("TURNSTILE_SECRET_KEY", "")

EMAIL_RE = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$"
)

def valid_email(value):
    return bool(EMAIL_RE.fullmatch(value.strip()))

def authenticated():
    return session.get("authenticated") is True

# =========================================================
# SPINTAX - DYNAMIC CONTENT GENERATOR
# =========================================================

SPINTAX_RE = re.compile(r"\{([^{}]+)\}")

def expand_spintax(text):
    if not text:
        return ""
    def replace_match(match):
        options = [
            option.strip()
            for option in match.group(1).split("|")
            if option.strip()
        ]
        if len(options) < 2:
            return match.group(0)
        return random.choice(options)

    while SPINTAX_RE.search(text):
        text = SPINTAX_RE.sub(replace_match, text)
    return text

def strip_html(html_text):
    """HTML content se plain text fallback banane ke liye"""
    clean = re.compile("<.*?>")
    return re.sub(clean, "", html_text)

# =========================================================
# TURNSTILE VERIFICATION
# =========================================================

def verify_turnstile(token, remote_ip=None):
    if not TURNSTILE_SECRET_KEY:
        return True, None

    if not token:
        return False, "Cloudflare verification is required."

    payload = {
        "secret": TURNSTILE_SECRET_KEY,
        "response": token
    }

    if remote_ip:
        payload["remoteip"] = remote_ip

    encoded = urllib.parse.urlencode(payload).encode("utf-8")

    req = urllib.request.Request(
        "https://challenges.cloudflare.com/turnstile/v0/siteverify",
        data=encoded,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST"
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
# AUTH ROUTES
# =========================================================

@app.route("/login", methods=["GET", "POST"])
def login():
    if authenticated():
        return redirect(url_for("home"))

    error = None

    if request.method == "POST":
        password = str(request.form.get("password", ""))
        configured_password = os.environ.get("LOGIN_PASSWORD") or os.environ.get("ADMIN_PASSWORD", "")

        if not configured_password:
            error = "LOGIN_PASSWORD is not configured."
        elif secrets.compare_digest(password, configured_password):
            session["authenticated"] = True
            return redirect(url_for("home"))
        else:
            error = "Incorrect password."

    return render_template("login.html", error=error)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/")
def home():
    if not authenticated():
        return redirect(url_for("login"))

    return render_template(
        "index.html",
        turnstile_site_key=os.environ.get("TURNSTILE_SITE_KEY", "")
    )

# =========================================================
# SEND BATCH - INBOX OPTIMIZED & FAST DURATION
# =========================================================

@app.route("/send-batch", methods=["POST"])
def send_batch():
    if not authenticated():
        return jsonify({
            "success": False,
            "message": "Authentication required."
        }), 401

    try:
        data = request.get_json(force=True, silent=True) or {}
    except Exception:
        return jsonify({"success": False, "message": "Invalid JSON payload."}), 400

    sender_name = str(data.get("sender_name", "")).strip()
    gmail = str(data.get("gmail", "")).strip().lower()
    app_password = str(data.get("app_password", "")).strip()
    subject = str(data.get("subject", "")).strip()
    body = str(data.get("body", ""))
    is_html = bool(data.get("is_html", False))
    recipients = data.get("recipients", [])
    turnstile_token = str(data.get("turnstile_token", "")).strip()

    if not sender_name:
        return jsonify({"success": False, "message": "Sender Name is required."}), 400

    if not valid_email(gmail):
        return jsonify({"success": False, "message": "Enter a valid Gmail address."}), 400

    if not app_password:
        return jsonify({"success": False, "message": "Google App Password is required."}), 400

    if not subject:
        return jsonify({"success": False, "message": "Email subject is required."}), 400

    if not body.strip():
        return jsonify({"success": False, "message": "Message body is required."}), 400

    if not isinstance(recipients, list):
        return jsonify({"success": False, "message": "Invalid recipient list."}), 400

    clean_recipients = []
    for item in recipients:
        email = str(item).strip().lower()
        if valid_email(email) and email not in clean_recipients:
            clean_recipients.append(email)

    clean_recipients = clean_recipients[:MAX_RECIPIENTS]

    if not clean_recipients:
        return jsonify({"success": False, "message": "No valid recipients found."}), 400

    verified, verify_error = verify_turnstile(
        turnstile_token,
        request.headers.get("X-Forwarded-For", request.remote_addr)
    )

    if not verified:
        return jsonify({"success": False, "message": verify_error}), 403

    @stream_with_context
    def generate():
        total = len(clean_recipients)
        sent_count = 0
        failed_count = 0
        remaining = total

        yield json.dumps({
            "type": "start",
            "total": total,
            "sent": 0,
            "failed": 0,
            "remaining": total
        }) + "\n"

        context = ssl.create_default_context()

        try:
            with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context, timeout=20) as server:
                server.login(gmail, app_password)

                for index, recipient in enumerate(clean_recipients, start=1):
                    try:
                        # Dynamic Spintax per email
                        final_subject = expand_spintax(subject)
                        final_body = expand_spintax(body)

                        # Dual Multipart structure for high inbox deliverability
                        msg = MIMEMultipart("alternative")
                        msg["From"] = formataddr((sender_name, gmail))
                        msg["To"] = recipient
                        msg["Subject"] = final_subject
                        msg["Date"] = formatdate(localtime=True)

                        # Clean headers to bypass spam filters
                        domain = gmail.split("@")[-1] if "@" in gmail else "gmail.com"
                        msg["Message-ID"] = make_msgid(domain=domain)
                        msg["X-Mailer"] = "ConsoleMailer/2.0"
                        msg["Auto-Submitted"] = "auto-generated"

                        if is_html:
                            # Adding Plain Text Fallback (Spam-filter rule)
                            plain_text_version = strip_html(final_body)
                            msg.attach(MIMEText(plain_text_version, "plain", "utf-8"))
                            msg.attach(MIMEText(final_body, "html", "utf-8"))
                        else:
                            msg.attach(MIMEText(final_body, "plain", "utf-8"))

                        server.sendmail(gmail, [recipient], msg.as_string())

                        sent_count += 1
                        remaining -= 1

                        yield json.dumps({
                            "type": "progress",
                            "email": recipient,
                            "result": "sent",
                            "total": total,
                            "sent": sent_count,
                            "failed": failed_count,
                            "remaining": remaining
                        }) + "\n"

                        # Requested High Speed (0.03 seconds)
                        time.sleep(0.03)

                        # Anti-Drop Safety: Har 50 mails ke baad micro-pause taaki Gmail socket clear kare
                        if index % 50 == 0:
                            time.sleep(0.5)

                    except Exception as exc:
                        failed_count += 1
                        remaining -= 1

                        yield json.dumps({
                            "type": "progress",
                            "email": recipient,
                            "result": "failed",
                            "error": str(exc),
                            "total": total,
                            "sent": sent_count,
                            "failed": failed_count,
                            "remaining": remaining
                        }) + "\n"

        except smtplib.SMTPAuthenticationError:
            yield json.dumps({
                "type": "error",
                "message": "Gmail authentication failed. Check Gmail and App Password.",
                "total": total,
                "sent": sent_count,
                "failed": failed_count,
                "remaining": remaining
            }) + "\n"
            return

        except smtplib.SMTPException as exc:
            yield json.dumps({
                "type
