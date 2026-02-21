
from app import app, db
from sqlalchemy import text

with app.app_context():
    try:
        db.session.execute(text("ALTER TABLE user ADD COLUMN status VARCHAR(20) DEFAULT 'pending'"))
        db.session.commit()
        print("✅ Column 'status' added successfully.")
    except Exception as e:
        print("⚠️ Error:", e)
