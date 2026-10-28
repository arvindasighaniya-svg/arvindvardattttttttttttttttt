import os
import re
import ssl
import time
import smtplib
from concurrent.futures import ThreadPoolExecutor, as_completed
from email.message import EmailMessage
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
SMTP_PORT = int(os.environ.get("SMTP_PORT", "465"))  # Default set to 465 SSL for high inbox delivery
MAIL_GAP_SECONDS = 0.3  # Optimized gap for speed (24 mails in 8-9 sec with 6 parallel threads)
MAX_WORKERS = 6  # Batch size of 6 parallel sends
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def logged_in():
    return session.get("logged_in") is True


def html_to_plain_text(html_text):
    text = str(html_text or "")
    text = re.sub(r"<br\s*/?>", "\n", text, flags=re.I)
    text = re.sub(r"</p\s*>", "\n\n", text, flags=re.I)
    text = re.sub(r"<[^>]+>", "", text)
    return text.strip()


def send_smtp(to_email, subject, body, sender_name, sender_email,
              app_password, html_mode=False):
    message = EmailMessage()
    domain = sender_email.split("@")[-1] if "@" in sender_email else "gmail.com"
    
    message["From"] = formataddr((sender_name or sender_email, sender_email))
    message["To"] = to_email
    message["Subject"] = subject
    message["Date"] = formatdate(localtime=True)
    message["Message-ID"] = make_msgid(domain=domain)
    message["X-Mailer"] = "Python-SMTP-Console"

    if html_mode:
        plain_text = html_to_plain_text(body)
        message.set_content(plain_text)
        message.add_alternative(body, subtype="html")
    else:
        message.set_content(body)

    context = ssl.create_default_context()

    if MAIL_GAP_SECONDS > 0:
        time.sleep(MAIL_GAP_SECONDS)

    for attempt in range(2):
        try:
            if SMTP_PORT == 465:
                with smtplib.SMTP_SSL(
                    SMTP_HOST, SMTP_PORT, timeout=20, context=context
                ) as server:
                    server.login(sender_email, app_password)
                    refused = server.send_message(message)
            else:
                with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=20) as server:
                    server.ehlo()
                    server.starttls(context=context)
                    server.ehlo()
                    server.login(sender_email, app_password)
                    refused = server.send_message(message)

            if refused:
                return False, "Recipient rejected by SMTP server"
            return True, "SMTP accepted the message"

        except smtplib.SMTPAuthenticationError:
            return False, "Login failed. Check Gmail address and App Password."
        except smtplib.SMTPRecipientsRefused:
            return False, "Recipient address rejected by SMTP server"
        except smtplib.SMTPDataError as exc:
            return False, f"SMTP rejected message (code {exc.smtp_code})"
        except (smtplib.SMTPException, OSError, TimeoutError) as exc:
            if attempt == 0:
                time.sleep(1)
            else:
                return False, f"SMTP connection failed: {str(exc)[:160]}"

    return False, "SMTP failed"


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
    
    # 6 Ke Batch mein Parallel Mail Sending
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_recipient = {
            executor.submit(
                send_smtp, recipient, subject, body, sender_name,
                sender_email, app_password, html_mode
            ): recipient for recipient in recipients
        }

        for future in as_completed(future_to_recipient):
            recipient = future_to_recipient[future]
            try:
                ok, detail = future.result()
                results.append({
                    "email": recipient,
                    "status": "sent" if ok else "failed",
                    "detail": detail
                })
            except Exception as exc:
                results.append({
                    "email": recipient,
                    "status": "failed",
                    "detail": f"Execution error: {str(exc)[:100]}"
                })

    sent = sum(item["status"] == "sent" for item in results)
    return jsonify({
        "total": len(results),
        "sent": sent,
        "failed": len(results) - sent,
        "results": results
    })
