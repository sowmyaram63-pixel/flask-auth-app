
from backend.src.app import app, db
from sqlalchemy import text

with app.app_context():
    print("🔍 DB URL:", db.engine.url)

    try:
        db.session.execute(text(
            "ALTER TABLE task ADD COLUMN section VARCHAR(50) DEFAULT 'recently_assigned' NOT NULL"
        ))
        db.session.commit()
        print("✅ Added column 'section' successfully!")
    except Exception as e:
        print("⚠️ Could not add column:", e)
