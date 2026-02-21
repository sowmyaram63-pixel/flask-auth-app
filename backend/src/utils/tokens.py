
from itsdangerous import URLSafeTimedSerializer
from flask import current_app

def get_serializer():
    return URLSafeTimedSerializer(current_app.config["SECRET_KEY"])

def generate_invite_token(data):
    s = get_serializer()
    return s.dumps(data, salt="invite-token")

def confirm_invite_token(token, expiration=86400):
    s = get_serializer()
    try:
        return s.loads(token, salt="invite-token", max_age=expiration)
    except Exception:
        return None
