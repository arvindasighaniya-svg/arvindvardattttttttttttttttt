import os
import json
import re
import smtplib
import random
import time
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formataddr, formatdate, make_msgid
from flask import Flask, render_template, request, jsonify, Response, session, redirect, url_for
import requests

# Fix Paths for Vercel Serverless Function Environment
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
TEMPLATE_DIR = os.path.join(BASE_DIR, 'templates')
STATIC_DIR = os.path.join(BASE_DIR, 'static')

app = Flask(__name__, template_folder=TEMPLATE_DIR, static_folder=STATIC_DIR)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "super-secret-key-change-this")

ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123")
TURNSTILE_SECRET_KEY = os.environ.get("TURNSTILE_SECRET_KEY", "")
TURNSTILE_SITE_KEY = os.environ.get("TURNSTILE_SITE_KEY", "")

def parse_spintax(text):
    """Spintax parser: {Hello|Hi|Hey} -> Random selection"""
    if not text:
        return ""
    pattern = re.compile(r'\{([^{}]+)\}')
    while pattern.search(text):
        text = pattern.sub(lambda m: random.choice(m.group(1).split('|')), text)
    return text

def verify_turnstile(token):
    if not TURNSTILE_SECRET_KEY:
        return True
    try:
        res = requests.post(
            "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            data={
                "secret": TURNSTILE_SECRET_KEY,
                "response": token
            },
            timeout=5
        )
        return res.json().get("success", False)
    except Exception:
        return False

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        pwd = request.form.get("password")
        if pwd == ADMIN_PASSWORD:
            session["logged_in"] = True
            return redirect(url_for("index"))
        else:
            error = "Invalid password!"
    return render_template("login.html", error=error)

@app.route("/logout")
def logout():
    session.pop("logged_in", None)
    return redirect(url_for("login"))

@app.route("/")
def index():
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    return render_template("index.html", turnstile_site_key=TURNSTILE_SITE_KEY)

@app.route("/send-batch", methods=["POST"])
def send_batch():
    if not session.get("logged_in"):
        return jsonify({"message": "Unauthorized"}), 401

    data = request.get_json() or {}
    sender_name = data.get("sender_name", "").strip()
    gmail = data.get("gmail", "").strip().lower()
    app_password = data.get("app_password", "").strip()
    subject = data.get("subject", "").strip()
    body = data.get("body", "")
    is_html = data.get("is_html", False)
    recipients = data.get("recipients", [])
    turnstile_token = data.get("turnstile_token", "")

    if not all([sender_name, gmail, app_password, subject, body, recipients]):
        return jsonify({"message": "Missing required fields."}), 400

    if TURNSTILE_SECRET_KEY and not verify_turnstile(turnstile_token):
        return jsonify({"message": "Cloudflare Turnstile verification failed."}), 400

    def generate_events():
        total = len(recipients)
        sent = 0
        failed = 0

        yield json.dumps({"type": "start", "total": total, "sent": 0, "failed": 0, "remaining": total}) + "\n"

        server = None
        try:
            # Connect to Google SMTP
            server = smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=10)
            server.login(gmail, app_password)
        except Exception as e:
            yield json.dumps({"type": "error", "message": f"SMTP Login Failed: {str(e)}", "total": total, "sent": 0, "failed": total, "remaining": 0}) + "\n"
            return

        for idx, recipient in enumerate(recipients):
            try:
                curr_subject = parse_spintax(subject)
                curr_body = parse_spintax(body)

                msg = MIMEMultipart("alternative")
                msg["From"] = formataddr((sender_name, gmail))
                msg["To"] = recipient
                msg["Subject"] = curr_subject
                msg["Date"] = formatdate(localtime=True)
                
                domain = gmail.split("@")[-1] if "@" in gmail else "gmail.com"
                msg["Message-ID"] = make_msgid(domain=domain)
                
                # High Deliverability Headers
                msg["X-Mailer"] = "Secure Mail Console v2.0"
                msg["Auto-Submitted"] = "auto-generated"

                if is_html:
                    msg.attach(MIMEText(curr_body, "html", "utf-8"))
                else:
                    msg.attach(MIMEText(curr_body, "plain", "utf-8"))

                server.sendmail(gmail, [recipient], msg.as_string())
                sent += 1

                # Reduced delay (0.5s - 1s) to prevent Vercel Function 10s Timeout
                time.sleep(random.uniform(0.5, 1.0))

            except Exception:
                failed += 1

            remaining = total - (sent + failed)
            yield json.dumps({"type": "progress", "total": total, "sent": sent, "failed": failed, "remaining": remaining}) + "\n"

        if server:
            try:
                server.quit()
            except Exception:
                pass

        yield json.dumps({"type": "complete", "total": total, "sent": sent, "failed": failed, "remaining": 0, "message": f"Done! Sent: {sent}, Failed: {failed}"}) + "\n"

    return Response(generate_events(), mimetype="application/x-ndjson")

# Expose app for Vercel
app = app
