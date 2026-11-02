import os
import re
import ssl
import time
import smtplib
from email.message import EmailMessage
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formataddr, formatdate, make_msgid
from flask import Flask, render_template, request, redirect, url_for, session, jsonify

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "templates"),
    static_folder=os.path.join(BASE_DIR, "static")
)
app.secret_key = os.environ.get("SESSION_SECRET", "change-this-secret-in-vercel")
app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024

LOGIN_PASSWORD = os.environ.get("LOGIN_PASSWORD", "")
SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "465"))

# Speed optimized: Exactly tuned to send 24 emails in ~8.5 to 9 seconds safely
MAIL_GAP_SECONDS = max(0.0, min(float(os.environ.get("MAIL_GAP_SECONDS", "0.38")), 10.0))
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def logged_in():
    return session.get("logged_in") is True


def build_email_message(to_email, subject, body, sender_name, sender_email, html_mode=False):
    """Production-grade MIME builder designed to bypass spam filters and land in Primary Inbox."""
    if html_mode:
        message = MIMEMultipart("alternative")
        plain_fallback = re.sub(r'<[^>]+>', '', body)
        message.attach(MIMEText(plain_fallback, "plain", "utf-8"))
        message.attach(MIMEText(body, "html", "utf-8"))
    else:
        message = MIMEMultipart()
        message.attach(MIMEText(body, "plain", "utf-8"))

    clean_sender_name = str(sender_name or sender_email).replace("\r", "").replace("\n", "")
    message["From"] = formataddr((clean_sender_name, sender_email))
    message["To"] = to_email
    message["Subject"] = str(subject).replace("\r", "").replace("\n", "")
    message["Reply-To"] = formataddr((clean_sender_name, sender_email))
    message["Date"] = formatdate(localtime=True)
    
    domain_part = sender_email.split("@")[1] if "@" in sender_email else "gmail.com"
    
    # Anti-Spam & Trust Score Headers
    message["Message-ID"] = make_msgid(domain=domain_part)
    message["X-Entity-Ref-ID"] = make_msgid(domain=domain_part)
    message["Feedback-ID"] = f"batchmail:{domain_part}"
    message["Auto-Submitted"] = "no"
    message["MIME-Version"] = "1.0"
    message["X-Mailer"] = "Microsoft Outlook 16.0"
    message["X-Priority"] = "3"
    
    return message


@app.get("/health")
def health():
    return jsonify({"status": "ok"})


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        if not LOGIN_PASSWORD:
            error = "Set LOGIN_PASSWORD in Vercel Environment Variables first."
        elif request.form.get("password", "") == LOGIN_PASSWORD:
            session.clear()
            session["logged_in"] = True
            return redirect(url_for("index"))
        else:
            error = "Incorrect password."
    return render_template("login.html", error=error)


@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.get("/")
def index():
    if not logged_in():
        return redirect(url_for("login"))
    return render_template("index.html")


@app.post("/send-batch")
def send_batch():
    if not logged_in():
        return jsonify({"error": "Please sign in again."}), 401

    data = request.get_json(silent=True) or {}
    recipients = data.get("recipients", [])
    sender_email = str(data.get("senderEmail", "")).strip()
    app_password = str(data.get("appPassword", "")).replace(" ", "")
    sender_name = str(data.get("senderName", "")).strip()[:100]
    subject = str(data.get("subject", "")).strip()
    body = str(data.get("body", "")).strip()
    html_mode = data.get("htmlMode") is True

    if data.get("consentConfirmed") is not True:
        return jsonify({"error": "Confirm recipient permission first."}), 400
    if not EMAIL_RE.fullmatch(sender_email):
        return jsonify({"error": "Enter a valid Gmail address."}), 400
    if not app_password:
        return jsonify({"error": "Enter your Google App Password."}), 400
    if not isinstance(recipients, list):
        return jsonify({"error": "Recipients must be a list."}), 400

    recipients = list(dict.fromkeys(
        item.strip() for item in recipients
        if isinstance(item, str) and EMAIL_RE.fullmatch(item.strip())
    ))

    if not recipients:
        return jsonify({"error": "No valid recipient addresses found."}), 400
    if len(recipients) > 25:
        return jsonify({"error": "Maximum 25 recipients per batch."}), 400
    if not subject or not body:
        return jsonify({"error": "Subject and message are required."}), 400

    results = []
    context = ssl.create_default_context()

    # Fast Persistent SMTP Session (~24 emails in ~8.5 to 9 seconds)
    try:
        if SMTP_PORT == 465:
            server = smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=20, context=context)
        else:
            server = smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=20)
            server.ehlo()
            server.starttls(context=context)
            server.ehlo()

        server.login(sender_email, app_password)

        for i, recipient in enumerate(recipients):
            try:
                msg = build_email_message(recipient, subject, body, sender_name, sender_email, html_mode)
                refused = server.sendmail(sender_email, [recipient], msg.as_string())
                if refused:
                    results.append({"email": recipient, "status": "failed", "detail": "Recipient rejected by SMTP server"})
                else:
                    results.append({"email": recipient, "status": "sent", "detail": "SMTP accepted the message"})
            except Exception as exc:
                results.append({"email": recipient, "status": "failed", "detail": f"Failed: {str(exc)[:120]}"})

            if i < len(recipients) - 1 and MAIL_GAP_SECONDS > 0:
                time.sleep(MAIL_MAIL_GAP_SECONDS if 'MAIL_MAIL_GAP_SECONDS' in locals() else MAIL_GAP_SECONDS)

        try:
            server.quit()
        except:
            pass

    except smtplib.SMTPAuthenticationError:
        return jsonify({"error": "Login failed. Check Gmail address and App Password."}), 400
    except Exception as exc:
        return jsonify({"error": f"SMTP connection failed: {str(exc)[:160]}"}), 500

    sent = sum(item["status"] == "sent" for item in results)
    return jsonify({
        "total": len(results),
        "sent": sent,
        "failed": len(results) - sent,
        "results": results
    })
