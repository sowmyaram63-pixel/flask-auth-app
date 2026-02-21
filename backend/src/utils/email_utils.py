
import os
import requests

RESEND_API_KEY = os.getenv("RESEND_API_KEY")
MAIL_FROM_EMAIL = os.getenv("MAIL_FROM_EMAIL")

def send_email(to, subject, html):
    if not RESEND_API_KEY:
        print("❌ Email error: Missing RESEND_API_KEY in .env")
        return False

    url = "https://api.resend.com/emails"
    headers = {
        "Authorization": f"Bearer {RESEND_API_KEY}",
        "Content-Type": "application/json"
    }

    data = {
        "from": MAIL_FROM_EMAIL,
        "to": to,
        "subject": subject,
        "html": html
    }

    try:
        response = requests.post(url, json=data, headers=headers)

        if response.status_code == 200 or response.status_code == 202:
            print("✅ Email sent successfully!")
            return True
        else:
            print("❌ Resend error:", response.status_code, response.text)
            return False

    except Exception as e:
        print("❌ Exception while sending email:", e)
        return False
