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

import re
import os
import json
import urllib.request
import urllib.parse
import secrets
import time

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
RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "").strip()

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
# CONSTANTS
# =========================================================

MAX_RECIPIENTS = 25
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
# RESEND API DISPATCH
# =========================================================

def send_via_resend(sender_name, sender_email, recipient, subject, body, is_html):
    if not RESEND_API_KEY:
        return {"result": "failed", "error": "RESEND_API_KEY is not set in environment."}

    headers = {
        "Authorization": f"Bearer {RESEND_API_KEY}",
        "Content-Type": "application/json",
    }

    payload = {
        "from": f"{sender_name} <{sender_email}>",
        "to": [recipient],
        "subject": subject,
    }

    if is_html:
        payload["html"] = body
        payload["text"] = html_to_plain_text(body)
    else:
        payload["text"] = body

    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request("https://api.resend.com/emails", data=data, headers=headers, method="POST")

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            if resp.status in (200, 201):
                return {"result": "sent"}
            return {"result": "failed", "error": f"HTTP {resp.status}"}
    except Exception as exc:
        return {"result": "failed", "error": str(exc)}


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


@app.route("/send-batch", methods=["POST"])
def send_batch():
    if not authenticated():
        return jsonify({"success": False, "message": "Authentication required."}), 401

    data = request.get_json(silent=True) or {}
    sender_name = clean_header(data.get("sender_name", ""), 200)
    sender_email = clean_header(data.get("gmail", ""), 254)
    subject = clean_header(data.get("subject", ""), 998)
    body = str(data.get("body", ""))
    is_html = data.get("is_html", False) is True
    recipients = data.get("recipients", [])
    turnstile_token = str(data.get("turnstile_token", "")).strip()

    if not sender_name or not valid_email(sender_email) or not subject or not body.strip():
        return jsonify({"success": False, "message": "All fields are required."}), 400

    clean_recipients = []
    seen = set()
    for item in recipients:
        email = normalize_email(item.get("email") if isinstance(item, dict) else item)
        if valid_email(email) and email not in seen:
            seen.add(email)
            clean_recipients.append(item if isinstance(item, dict) else {"email": email})

    clean_recipients = clean_recipients[:MAX_RECIPIENTS]
    if not clean_recipients:
        return jsonify({"success": False, "message": "No valid recipients found."}), 400

    forwarded_for = request.headers.get("X-Forwarded-For")
    remote_ip = forwarded_for.split(",", 1)[0].strip() if forwarded_for else request.remote_addr
    verified, verify_error = verify_turnstile(turnstile_token, remote_ip)
    if not verified:
        return jsonify({"success": False, "message": verify_error}), 403

    @stream_with_context
    def generate():
        total = len(clean_recipients)
        sent_count = 0
        failed_count = 0

        yield json.dumps({"type": "start", "total": total, "sent": 0, "failed": 0, "remaining": total}) + "\n"

        for recipient_data in clean_recipients:
            rec_email = recipient_data["email"]
            p_sub = personalize_template(subject, recipient_data)
            p_body = personalize_template(body, recipient_data)

            res = send_via_resend(sender_name, sender_email, rec_email, p_sub, p_body, is_html)

            if res["result"] == "sent":
                sent_count += 1
            else:
                failed_count += 1

            yield json.dumps({
                "type": "progress",
                "email": rec_email,
                "result": res["result"],
                "total": total,
                "sent": sent_count,
                "failed": failed_count,
                "remaining": total - sent_count - failed_count,
                "error": res.get("error"),
            }) + "\n"

            time.sleep(0.5)

        yield json.dumps({
            "type": "complete",
            "success": True,
            "total": total,
            "sent": sent_count,
            "failed": failed_count,
        }) + "\n"

    response = Response(generate(), content_type="application/x-ndjson; charset=utf-8")
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    return response


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
