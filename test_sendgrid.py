import os
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from dotenv import load_dotenv

# Load variables from .env
load_dotenv()

message = Mail(
    from_email=os.getenv("MAIL_FROM_EMAIL"),
    to_emails="sowmyaram63@gmail.com",  
    subject="Test Email from SendGrid",
    plain_text_content="If you see this, SendGrid is working 🎉"
)

try:
    sg = SendGridAPIClient(os.getenv("SENDGRID_API_KEY"))
    response = sg.send(message)
    print("Status Code:", response.status_code)
    print("Body:", response.body)
    print("Headers:", response.headers)
except Exception as e:
    print("Error:", e)

