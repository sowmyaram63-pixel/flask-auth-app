
import os
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

message = Mail(
    from_email=os.getenv("MAIL_FROM_EMAIL"),
    to_emails="yourEmail@gmail.com",
    subject="Test Email",
    html_content="<h1>Hello from raw SendGrid test</h1>"
)

try:
    sg = SendGridAPIClient(os.getenv("SENDGRID_API_KEY"))
    response = sg.send(message)
    print("Status:", response.status_code)
except Exception as e:
    print("Error:", e)
