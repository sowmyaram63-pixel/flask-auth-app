
from dotenv import load_dotenv
load_dotenv("/Users/sowmya/GearFlow/clean-app/.env")
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from authlib.integrations.flask_client import OAuth
from datetime import date, datetime, timedelta
import calendar
from werkzeug.utils import secure_filename
from flask_session import Session
from .extensions import db, mail,migrate,login_manager
from .models import User, Connection, Project, Task, Notification,get_pill_color,ChatRoom,ChatMember,ChatMessage,Reminder
from werkzeug.middleware.proxy_fix import ProxyFix
import secrets, os, random, time
from datetime import date
from flask_login import (
    LoginManager,
    login_user,
    logout_user,
    login_required,
    current_user
)

from PIL import Image
import pillow_heif  
pillow_heif.register_heif_opener()
import certifi
import ssl
import urllib3
from apscheduler.schedulers.background import BackgroundScheduler
from .utils.email_utils import send_email
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Message
from .utils.tokens import generate_invite_token, confirm_invite_token
from flask_socketio import SocketIO,join_room, leave_room, emit
from flask import current_app

# -------------------------------
# Load environment
# -------------------------------

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))
FRONTEND_DIR = os.path.join(PROJECT_ROOT, 'frontend')
dotenv_path = os.path.join(PROJECT_ROOT, ".env")
if os.path.exists(dotenv_path):
    load_dotenv(dotenv_path)
    print(f"✅ Loaded .env from {dotenv_path}")
else:
    print(f"❌ .env not found at {dotenv_path}")

# -------------------------------
# Detect environment
# -------------------------------
IS_RAILWAY = "RAILWAY_ENVIRONMENT" in os.environ or "RAILWAY_STATIC_URL" in os.environ
LOCAL_HOST = not IS_RAILWAY

# -------------------------------
# Credentials and redirect URI
# -------------------------------
if IS_RAILWAY:
    GOOGLE_CLIENT_ID = os.getenv("PROD_GOOGLE_CLIENT_ID")
    GOOGLE_CLIENT_SECRET = os.getenv("PROD_GOOGLE_CLIENT_SECRET")
    REDIRECT_URI = "https://web-production-1ac09.up.railway.app/login/google/authorized"
else:
    GOOGLE_CLIENT_ID = os.getenv("LOCAL_GOOGLE_CLIENT_ID")
    GOOGLE_CLIENT_SECRET = os.getenv("LOCAL_GOOGLE_CLIENT_SECRET")
    REDIRECT_URI = os.getenv("REDIRECT_URI")

SECRET_KEY = os.getenv("SECRET_KEY", "fallback_secret_key")

print("🔍 Loading environment variables...")
print("GOOGLE_CLIENT_ID:", GOOGLE_CLIENT_ID)
print("GOOGLE_CLIENT_SECRET:", GOOGLE_CLIENT_SECRET)
print("REDIRECT_URI:", REDIRECT_URI)

if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
    raise Exception("⚠️ GOOGLE_CLIENT_ID or GOOGLE_CLIENT_SECRET not set in environment!")

# -------------------------------
# Flask app
# -------------------------------
app = Flask(
    __name__,
    template_folder=os.path.join(FRONTEND_DIR, 'templates'),
    static_folder=os.path.join(FRONTEND_DIR, 'static')
)
socketio = SocketIO(app,cors_allowed_origins="*")
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-key-change-me")

serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"])
# Detect environment
on_railway = os.getenv("RAILWAY_ENVIRONMENT") is not None

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
INSTANCE_PATH = os.path.join(BASE_DIR, "../instance")

if on_railway:
    # ✅ Use Railway Postgres
    app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL").replace("postgres://", "postgresql://")
else:
    # ✅ Use local SQLite
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:////Users/sowmya/GearFlow/clean-app/instance/users_restored.db"

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_TYPE'] = 'filesystem'
app.config["SESSION_PERMANENT"] = False
app.config['SESSION_COOKIE_SECURE'] = IS_RAILWAY
app.config['SESSION_COOKIE_SAMESITE'] = "None" if IS_RAILWAY else "Lax"
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['OAUTHLIB_INSECURE_TRANSPORT'] = LOCAL_HOST
app.debug = True
app.config['PROPAGATE_EXCEPTIONS'] = True
app.config['SQLALCHEMY_ECHO']=True
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.jinja_env.cache = {}
Session(app)
print("🔥 USING DB:", app.config.get("SQLALCHEMY_DATABASE_URI"))
# -------------------------------
# Uploads config
# -------------------------------
from flask_mail import Mail, Message

app.config["MAIL_SERVER"] = os.environ.get("MAIL_SERVER")
app.config["MAIL_PORT"] = int(os.environ.get("MAIL_PORT", 587))
app.config["MAIL_USE_TLS"] = os.environ.get("MAIL_USE_TLS", "true").lower() == "true"

app.config["MAIL_USERNAME"] = os.environ.get("MAIL_USERNAME")
app.config["MAIL_PASSWORD"] = os.environ.get("MAIL_PASSWORD")
app.config["MAIL_DEFAULT_SENDER"] = os.environ.get("MAIL_DEFAULT_SENDER")

mail = Mail(app)


UPLOAD_SUBFOLDER = "uploads"
UPLOAD_FOLDER = os.path.join(app.static_folder, "uploads")
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# simple deterministic avatar color generator
AVATAR_COLORS = [
  "#0b57ff","#0f766e","#be185d","#7c3aed","#ea580c","#059669","#a16207","#0ea5a4","#0ea5a4","#ef4444"
]

def get_avatar_color(name):
    if not name: return "#94a3b8"
    s = sum(ord(c) for c in str(name))
    return AVATAR_COLORS[s % len(AVATAR_COLORS)]

# expose to jinja
app.jinja_env.globals.update(get_avatar_color=get_avatar_color)

@app.route("/test-email")
@login_required
def test_email():
    msg = Message(
        subject="GearFlow Test Email",
        recipients=[current_user.email],
        body="Mailgun SMTP is working 🎉"
    )
    mail.send(msg)
    return "Email sent!"

def seed_data():
    from datetime import datetime
    from .models import User, Project

    # ⛔ Skip seeding during migrations
    if current_app.config.get("MIGRATION_MODE"):
        print("⚠ Skipping seed during migration")
        return

    try:
        count = User.query.count()
    except Exception as e:
        print("⚠ DB not ready yet, skipping seed")
        return

    if count == 0:
        print("🌱 Seeding initial data...")

        admin = User(
            name="Admin",
            email="admin@example.com",
            password="admin123",
            role="admin"
        )

        db.session.add(admin)
        db.session.commit()

        project1 = Project(
            title="AI Research",
            description="Exploring ML models and deep learning.",
            owner_id=admin.id,
            created_at=datetime.now()
        )

        db.session.add(project1)
        db.session.commit()

        print("✅ Seeding completed successfully!")
    else:
        print("ℹ️ Database already seeded — skipping.")



# -------------------------------
# DB init
# -------------------------------
db.init_app(app)
migrate.init_app(app, db)

login_manager.init_app(app)
login_manager.login_view = "login"

# ✅ Ensure the instance folder exists
os.makedirs(app.instance_path, exist_ok=True)

# ✅ Use the same database path Flask points to
db_path = os.path.join(app.instance_path, "users_restored.db")

if not os.path.exists(db_path):
    print(f"🧱 Creating new database at: {db_path}")
    with app.app_context():
        db.create_all()
        seed_data()
else:
    print(f"✅ Using existing database: {db_path}")

# -------------------------------
# OAuth (Google)
# -------------------------------
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'},
)

# -------------------------------
# Google Login / Callback
# -------------------------------
from flask import g
from flask_login import login_user, logout_user, login_required, current_user


@app.route("/login/google")
def google_login():
    return google.authorize_redirect(REDIRECT_URI)

@app.route("/login/google/authorized")
def google_authorized():
    try:
        token = google.authorize_access_token()
        resp = google.get("https://www.googleapis.com/oauth2/v3/userinfo")
        userinfo = resp.json()

        email = userinfo.get("email")
        name = userinfo.get("name")
        picture = userinfo.get("picture")

        if not email:
            flash("Google login failed.", "danger")
            return redirect(url_for("login"))

        user = User.query.filter_by(email=email).first()
        if not user:
            user = User(
                name=name,
                email=email,
                avatar_url=picture,
                role="employee"
            )
            db.session.add(user)
            db.session.commit()

        # ✅ THIS is all you need
        login_user(user)

        flash(f"Welcome {user.name}!", "success")
        return redirect(url_for("home"))

    except Exception as e:
        app.logger.exception("Google OAuth error")
        flash("Google login failed.", "danger")
        return redirect(url_for("login"))



@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

from datetime import datetime, date
from flask import request, render_template
from sqlalchemy import func

@app.route("/home")
@login_required
def home():
    user = current_user

    now = datetime.now()
    today = date.today()
    tab = request.args.get("tab", "upcoming")

    # ---------------- REMINDERS ---------------- #

    today_reminders = Reminder.query.filter(
        Reminder.user_id == user.id,
        Reminder.done == False,
        func.date(Reminder.remind_at) == today
    ).order_by(Reminder.remind_at).all()

    upcoming_reminders = Reminder.query.filter(
        Reminder.user_id == user.id,
        Reminder.done == False,
        Reminder.remind_at > now,
        func.date(Reminder.remind_at) != today
    ).order_by(Reminder.remind_at).limit(5).all()

    overdue_reminders = Reminder.query.filter(
        Reminder.user_id == user.id,
        Reminder.done == False,
        Reminder.remind_at < now
    ).order_by(Reminder.remind_at).all()

    # ---------------- TASKS ---------------- #

    if tab == "upcoming":
        tasks = Task.query.filter(
            Task.assignee_id == user.id,
            Task.due_date.isnot(None),
            Task.due_date > today,
            Task.status != "done"
        ).order_by(Task.due_date.asc()).all()

    elif tab == "today":
        tasks = Task.query.filter(
            Task.assignee_id == user.id,
            Task.due_date.isnot(None),
            func.date(Task.due_date) == today,
            Task.status != "done"
        ).order_by(Task.due_date.asc()).all()

    elif tab == "overdue":
        tasks = Task.query.filter(
            Task.assignee_id == user.id,
            Task.due_date < today,
            Task.status != "done"
        ).order_by(Task.due_date.asc()).all()

    elif tab == "completed":
        tasks = Task.query.filter(
            Task.assignee_id == user.id,
            Task.status == "done"
        ).order_by(Task.due_date.desc()).all()

    else:
        tasks = []

    overdue_count = Task.query.filter(
        Task.assignee_id == user.id,
        Task.due_date.isnot(None),
        func.date(Task.due_date) < today,
        Task.status != "done"
    ).count()

    today_count = Task.query.filter(
        Task.assignee_id == user.id,
        Task.due_date.isnot(None),
        func.date(Task.due_date) == today,
        Task.status != "done"
    ).count()

    upcoming_count = Task.query.filter(
        Task.assignee_id == user.id,
        Task.due_date.isnot(None),
        func.date(Task.due_date) > today,
        Task.status != "done"
    ).count()

    completed_count = Task.query.filter(
        Task.assignee_id == user.id,
        Task.status == "done"
    ).count()

    greeting_time = (
        "morning" if 5 <= now.hour < 12
        else "afternoon" if 12 <= now.hour < 18
        else "evening"
    )

    return render_template(
        "home.html",
        user=user,
        tasks=tasks,
        active_tab=tab,
        overdue_count=overdue_count,
        today_count=today_count,
        upcoming_count=upcoming_count,
        completed_count=completed_count,
        current_date=now.strftime("%A, %B %d"),
        greeting_time=greeting_time,

        # 👇 NEW VARIABLES
        today_reminders=today_reminders,
        upcoming_reminders=upcoming_reminders,
        overdue_reminders=overdue_reminders,

        page="home"
    )

@app.route("/work")
def work_section():
    return render_template("work_dashboard.html", section="work")


@app.route("/dashboard")
def dashboard():
    if 'google_id' not in session:
        return redirect(url_for('google_login'))
    return render_template("index.html")

@app.route("/__debug_state")
def debug_state():
    from flask import jsonify
    try:
        sess_keys = {k: (v if k in ("user_id","user_email","user_name") else "REDACTED") for k, v in dict(session).items()}
        user_count = db.session.execute("SELECT COUNT(*) FROM user").scalar()
        project_count = db.session.execute("SELECT COUNT(*) FROM project").scalar()
        task_count = db.session.execute("SELECT COUNT(*) FROM task").scalar()

        users = [dict(r) for r in db.session.execute("SELECT id,name,email FROM user LIMIT 10")]
        projects = [dict(r) for r in db.session.execute("SELECT id,title,owner_id FROM project LIMIT 10")]
        tasks = [dict(r) for r in db.session.execute("SELECT id,title,assignee_id,project_id FROM task LIMIT 10")]

        return jsonify({
            "session": sess_keys,
            "counts": {"users": user_count, "projects": project_count, "tasks": task_count},
            "users": users,
            "projects": projects,
            "tasks": tasks
        })
    except Exception as e:
        return jsonify({"error": str(e)})
  
@app.route("/__debug_redirect")
def debug_redirect():
    from flask import jsonify, url_for
    return jsonify({
        "RAILWAY_STATIC_URL": os.getenv("RAILWAY_STATIC_URL"),
        "REDIRECT_URI_env": os.getenv("REDIRECT_URI"),
        "computed_redirect": url_for("google_authorized", _external=True)
    })

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        name = request.form.get("name") 
        email = request.form["email"]
        password = generate_password_hash(request.form["password"], method="pbkdf2:sha256")

        
        if User.query.filter_by(email=email).first():
            return render_template("auth/signup.html", error="User already exists")

    
        user = User(name=name, email=email, password=password)
        db.session.add(user)
        db.session.commit()
        login_user(user)

        return redirect(url_for("home"))

    return render_template("auth/signup.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            flash("Logged in successfully!", "success")
            return redirect(url_for("home"))

        flash("Invalid email or password.", "danger")

    return render_template("auth/login.html")




def generate_avatar_style(name):
    if not name:
        return "?", "#cccccc"

    parts = name.split()
    initials = "".join([p[0] for p in parts[:2]]).upper()

    colors = ["#A6E3E9", "#FFB5E8", "#B5EAD7", "#FFDAC1", "#E2F0CB", "#C7CEEA"]
    index = sum(ord(c) for c in initials) % len(colors)

    return initials, colors[index]


@app.context_processor
def inject_user():
    return {"user": current_user}

@app.route("/profile")
@login_required
def profile():
    user = current_user
    tasks = Task.query.filter_by(assignee_id=user.id).all()

    return render_template(
        "profile/profile.html",
        user=user,
        tasks=tasks,
    )


@app.route("/edit_profile", methods=["POST"])
def edit_profile():
    
    user = current_user
    user.name = request.form.get("name")
    user.job_title = request.form.get("job_title")
    user.team = request.form.get("team")
    user.about_me = request.form.get("about_me")

    file = request.files.get("avatar")
    if file and file.filename:
        filename = secure_filename(f"user_{user.id}_{int(time.time())}.png")
        filepath = os.path.join(app.static_folder, "uploads", filename)
        file.save(filepath)
        user.avatar_url = url_for("static", filename=f"uploads/{filename}")

    db.session.commit()
    flash("Profile updated.", "success")
    return redirect("/profile")


@app.route("/update_profile", methods=["GET", "POST"])
@login_required
def update_profile():
    user = current_user

    user = db.session.get(User, session["user_id"])

    if request.method == "POST":
        # Basic fields
        user.name = request.form.get("name", user.name)
        user.phone = request.form.get("phone", user.phone)
        user.bio = request.form.get("bio", user.bio)

        # Update password only if provided
        pw = request.form.get("password", "")
        if pw:
            user.password = generate_password_hash(pw, method="pbkdf2:sha256")

        # Handle avatar removal checkbox (optional)
        if request.form.get("remove_avatar") == "on":
            user.avatar_url = None

        # Handle avatar file upload
        file = request.files.get("avatar_file")
        avatar_url_input = (request.form.get("avatar_url") or "").strip()

        if file and file.filename:
            # create a safe, unique filename
            filename = secure_filename(f"{session['user_id']}_{int(time.time())}_{file.filename}")
            save_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            file.save(save_path)

            # store a web URL that points to /static/uploads/<filename>
            user.avatar_url = url_for("static", filename=f"{UPLOAD_SUBFOLDER}/{filename}")
            app.logger.info("Saved avatar to %s, stored url %s", save_path, user.avatar_url)

        elif avatar_url_input:
            # store the provided external URL directly
            user.avatar_url = avatar_url_input

        # commit changes
        db.session.commit()
        return redirect(url_for("profile"))

    return render_template("profile/updateprofile.html", user=user)

@app.route("/logout")
def logout():
    logout_user()
    flash("Logged out successfully!", "info")
    return redirect(url_for("login"))


@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form["email"]
        user = User.query.filter_by(email=email).first()

        if not user:
            return render_template("auth/forgot.html", error="No account found with that email.")

        otp = f"{random.randint(100000, 999999)}"
        expiry = int(time.time()) + 300  # 5 mins

        session["reset_email"] = email
        session["reset_otp"] = otp
        session["reset_otp_expiry"] = expiry

        # Send via Resend
        send_email(
            email,
            "Your GearFlow OTP",
            f"<h2>Your OTP is <b>{otp}</b></h2><p>Valid for 5 minutes.</p>"
        )

        return redirect(url_for("verify_otp"))

    return render_template("auth/forgot.html")

@app.route("/verify_otp", methods=["GET", "POST"])
def verify_otp():
    if "reset_email" not in session:
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        user_otp = request.form["otp"]
        real_otp = session.get("reset_otp")
        expiry = session.get("reset_otp_expiry")

        if int(time.time()) > expiry:
            return render_template("auth/verify.html", error="OTP expired. Please request a new one.")

        if user_otp != real_otp:
            return render_template("auth/verify.html", error="Incorrect OTP. Try again.")

        session["otp_verified"] = True
        return redirect(url_for("reset_password"))

    return render_template("auth/verify.html")


@app.route("/reset_password", methods=["GET", "POST"])
def reset_password():
    if not session.get("otp_verified"):
        return redirect(url_for("forgot_password"))

    email = session.get("reset_email")
    user = User.query.filter_by(email=email).first()

    if request.method == "POST":
        new_pass = request.form["password"]
        user.password = generate_password_hash(new_pass, method="pbkdf2:sha256")
        db.session.commit()

        # clear session
        session.pop("reset_email", None)
        session.pop("reset_otp", None)
        session.pop("reset_otp_expiry", None)
        session.pop("otp_verified", None)

        return redirect(url_for("login"))

    return render_template("auth/reset.html")


@app.route("/search", methods=["GET", "POST"])
@login_required
def search():
    

    query = request.form.get("query", "")
    
    results = []
    
    if query:
        results = User.query.filter(User.name.ilike(f"%{query}%"), User.id != session["user_id"]).all()

    return render_template("search.html", users=results)
           
@app.route("/connect/<int:user_id>/<action>")
@login_required
def connect(user_id, action):

    from_user = session["user_id"]
    to_user = user_id

    conn = Connection.query.filter_by(from_user_id=from_user, to_user_id=to_user).first()
    if not conn:
        conn = Connection(from_user_id=from_user, to_user_id=to_user, status="pending")
        db.session.add(conn)

    if action == "accept":
        conn.status = "accepted"
    elif action == "reject":
        conn.status = "rejected"

    db.session.commit()
    return redirect(url_for("search"))

@app.route("/all_profiles")
@login_required
def all_profiles():
    

    current_user_id = session["user_id"]

    # Accepted users
    accepted_users = (
        db.session.query(User)
        .join(Connection, Connection.to_user_id == User.id)
        .filter(Connection.from_user_id == current_user_id, Connection.status == "accepted")
        .all()
    )

    # Rejected users
    rejected_users = (
        db.session.query(User)
        .join(Connection, Connection.to_user_id == User.id)
        .filter(Connection.from_user_id == current_user_id, Connection.status == "rejected")
        .all()
    )

    # Pending users
    pending_users = (
        db.session.query(User)
        .join(Connection, Connection.to_user_id == User.id)
        .filter(Connection.from_user_id == current_user_id, Connection.status == "pending")
        .all()
    )

    return render_template(
        "profile/all_profiles.html",
        accepted_users=accepted_users,
        rejected_users=rejected_users,
        pending_users=pending_users,
    )
# -----------------------
# Project Routes
# ----------------------

def add_notification(user_id, message):
    """Adds a notification for a specific user."""
    notification = Notification(user_id=user_id, message=message)
    db.session.add(notification)
    db.session.commit()

@app.route("/projects/create", methods=["GET", "POST"])
@login_required
def create_project():
    


    if request.method == "POST":
        title = request.form["title"]
        description = request.form["description"]

        new_p = Project(
            title=title,
            description=description,
            owner_id=current_user.id
           
        )
        db.session.add(new_p)
        db.session.commit()
        return redirect("/projects")

    return render_template("projects/create_project.html")

from flask_login import login_required, current_user

@app.route("/projects")
@login_required
def browse_projects():
    user = current_user

    projects = Project.query.filter_by(owner_id=user.id).all()

    return render_template(
        "projects/browse_projects.html",
        user=user,
        projects=projects,
        page="projects"
    )


@app.route("/projects/<int:project_id>/list")
@login_required
def project_list_view(project_id):
    
    user = current_user
    project = Project.query.filter_by(
        id=project_id,
        owner_id=user.id
    ).first_or_404()
    tasks = Task.query.filter_by(project_id=project.id).all()

    sections = {
        "To do": [t for t in tasks if t.status in ["todo", None, ""]],
        "In progress": [t for t in tasks if t.status == "in-progress"],
        "Done": [t for t in tasks if t.status == "done"],
    }

    return render_template(
        "projects/project_list.html",
        project=project,
        tasks=tasks,
        sections=sections,
        active_tab="list",
        user = user
    )

@app.route("/projects/<int:project_id>/tasks_panel")
def project_tasks_panel(project_id):
    
    project = Project.query.filter_by(
        id=project_id,
        owner_id=current_user.id
    ).first_or_404()
    tasks = Task.query.filter_by(project_id=project.id).all()
    users = User.query.all()

    return render_template("tasks/project_tasks_panel.html", project=project, tasks=tasks, users=users)

@app.route("/projects/<int:project_id>/overview")
@login_required
def project_overview(project_id):
    user = current_user
    project = Project.query.filter_by(id=project_id, owner_id=user.id).first_or_404()
    tasks = Task.query.filter_by(project_id=project.id).all()

    completed = sum(1 for t in tasks if t.status == "done")
    progress = sum(1 for t in tasks if t.status == "in-progress")
    todo = sum(1 for t in tasks if t.status in ["todo", None, ""])

    return render_template(
        "projects/project_overview.html",
        project=project,
        tasks=tasks,
        completed_count=completed,
        progress_count=progress,
        todo_count=todo,
        active_tab="overview",
        user=user,
        page="projects"
    )



@app.route("/projects/<int:project_id>/board")
@login_required
def project_board(project_id):
    
    user = current_user
    project = Project.query.get_or_404(project_id)
    tasks = Task.query.filter_by(project_id=project.id).all()

    columns = {
        "To do": [t for t in tasks if t.status in ["todo", None, ""]],
        "In progress": [t for t in tasks if t.status == "in-progress"],
        "Done": [t for t in tasks if t.status == "done"]
    }

    return render_template(
        "projects/project_board.html",
        project=project,
        columns=columns,
        active_tab="board",
        user = user
    )

@app.route("/projects/<int:project_id>/timeline")
@login_required
def project_timeline(project_id):
    
    user = current_user
    project = Project.query.get_or_404(project_id)
    tasks = Task.query.filter_by(project_id=project.id).all()

    return render_template(
        "projects/project_timeline.html",
        project=project,
        tasks=tasks,
        active_tab="timeline",
        user = user
    )
@app.route("/projects/<int:project_id>/dashboard")
@login_required
def project_dashboard(project_id):

    user = current_user
    project = Project.query.get_or_404(project_id)
    tasks = Task.query.filter_by(project_id=project.id).all()

    high_priority = sum(1 for t in tasks if t.priority == "High")
    due_soon = sum(1 for t in tasks if t.due_date)

    completed = sum(1 for t in tasks if t.status == "done")

    return render_template(
        "projects/project_dashboard.html",
        project=project,
        tasks=tasks,
        high_priority=high_priority,
        due_soon=due_soon,
        completed_count=completed,
        active_tab="dashboard",
        user = user
    )

from datetime import timedelta, date

def build_calendar(tasks):
    today = date.today()
    days = []

    for i in range(30):  # Show next 30 days
        day_date = today + timedelta(days=i)
        day_tasks = [t for t in tasks if t.due_date == day_date]

        days.append({
            "date": day_date.strftime("%b %d"),
            "tasks": day_tasks
        })

    return days
@app.route("/projects/<int:project_id>/calendar")
@login_required
def project_calendar(project_id):
    user = current_user
    project = Project.query.get_or_404(project_id)
    tasks = Task.query.filter_by(project_id=project_id).all()

    calendar_tasks = []

    for t in tasks:
        if t.due_date:
            date_str = t.due_date.strftime("%Y-%m-%d")
        else:
            # skip tasks with no due date (calendar cannot place them)
            continue

        calendar_tasks.append({
            "title": t.title or "Untitled",
            "date": date_str
        })

    return render_template(
        "projects/project_calendar.html",
        project=project,
        calendar_tasks=calendar_tasks,
        active_tab="calendar",
        user = user
    )

@app.route("/projects/<int:project_id>/files")
@login_required
def project_files(project_id):

    project = Project.query.get_or_404(project_id)
    user = current_user
    # File model optional: here using local folder
    import os
    upload_path = f"frontend/static/uploads/project_{project.id}"

    if not os.path.exists(upload_path):
        os.makedirs(upload_path)

    files = [
        {"filename": f, "url": f"/static/uploads/project_{project.id}/{f}"}
        for f in os.listdir(upload_path)
    ]

    return render_template(
        "projects/project_files.html",
        project=project,
        files=files,
        active_tab="files",
        user = user
    )

@app.route("/projects/<int:project_id>/files/upload", methods=["POST"])
@login_required
def project_files_upload(project_id):

    project = Project.query.filter_by(
        id=project_id,
        owner_id=current_user.id
    ).first_or_404()

    file = request.files["file"]
    filename = secure_filename(file.filename)

    path = f"frontend/static/uploads/project_{project.id}"

    if not os.path.exists(path):
        os.makedirs(path)

    file.save(os.path.join(path, filename))

    return redirect(f"/projects/{project_id}/files")


@app.route("/projects/<int:project_id>/add_task", methods=["GET", "POST"])
@login_required
def add_task_to_project(project_id):
    

    project = Project.query.get_or_404(project_id)
    users = User.query.all()

    if request.method == "POST":
        title = request.form.get("title")
        description = request.form.get("description")
        assignee_id = request.form.get("assignee_id") or None
        due_date_str = request.form.get("due_date")
        priority = request.form.get("priority", "Medium")

        from datetime import datetime
        due_date = datetime.strptime(due_date_str, "%Y-%m-%d").date() if due_date_str else None

        task = Task(
            title=title,
            description=description,
            project_id=project.id,
            assignee_id=assignee_id if assignee_id else None,
            due_date=due_date,
            status="",
            assigned_by_id=current_user.id,
            priority=priority
        )
        db.session.add(task)
        db.session.commit()

        # ✅ Send email to assignee if provided
        if assignee_id:
            assignee = User.query.get(int(assignee_id))
            if assignee and assignee.email:
                subject = f"New Task Assigned: {title}"
                body = f"""
                <p>Hi {assignee.name or 'there'},</p>
                <p>You’ve been assigned a new task in <b>{project.title}</b>.</p>
                <p><b>Task:</b> {title}</p>
                <p><b>Description:</b> {description or 'No description provided.'}</p>
                <p><b>Due Date:</b> {due_date or 'Not specified'}</p>
                <br>
                <p>Login to your GearFlow dashboard to check your tasks.</p>
                <p style="color:#555;">- The GearFlow Team</p>
                """
                send_email(assignee.email, subject, body)

        flash("✅ Task created successfully!", "success")
        return redirect(url_for("project_detail", project_id=project.id))
    
    return render_template("tasks/create_task.html", project=project, users=users)


def group_tasks_for_user(user):
    """Return tasks grouped by section for the Asana-style board."""
    tasks = Task.query.filter_by(assignee_id=user.id).order_by(
        Task.due_date.asc().nulls_last()
    ).all()

    grouped = {
        "recently_assigned": [],
        "do_today": [],
        "do_next_week": [],
        "do_later": []
    }

    today = date.today()

    for t in tasks:
        section = (t.section or "").lower()

        if section in grouped:
            grouped[section].append(t)
        else:
            # fallback if old tasks have no section yet
            if t.due_date == today:
                grouped["do_today"].append(t)
            elif t.due_date and (t.due_date - today).days <= 7:
                grouped["do_next_week"].append(t)
            else:
                grouped["do_later"].append(t)

    return grouped


@app.route("/tasks/<int:task_id>/move_section", methods=["POST"])
@login_required
def move_section(task_id):

    data = request.get_json(force=True)
    new_section = data.get("section")

    # Allowed sections for the board
    valid_sections = [
        "recently_assigned",
        "do_today",
        "do_next_week",
        "do_later"
    ]

    if new_section not in valid_sections:
        return jsonify({"ok": False, "error": "Invalid section"}), 400

    task = Task.query.get(task_id)
    if not task:
        return jsonify({"ok": False, "error": "Task not found"}), 404

    # Permission check
    user = current_user
    if user.role != "admin" and task.assignee_id != user.id:
        return jsonify({"ok": False, "error": "Permission denied"}), 403

    # Update DB section
    task.section = new_section

    # Auto-update status (Asana-like behavior)
    status_map = {
        "recently_assigned": "todo",
        "do_today": "in-progress",
        "do_next_week": "todo",
        "do_later": "todo"
    }
    task.status = status_map.get(new_section, task.status)

    db.session.commit()

    return jsonify({"ok": True, "task_id": task.id, "section": task.section})

# -----------------------
# Task Routes
# -----------------------

from datetime import datetime
from datetime import date


@app.route("/update_activity", methods=["GET", "POST"])
def update_activity():
    if "user_id" not in session:
        return redirect(url_for("login"))

    user = User.query.get(session["user_id"])

    if request.method == "POST":
        activity = request.form.get("activity", "").strip()
        if activity:
            user.recent_activity = activity
            db.session.commit()
            flash("Activity updated successfully!", "success")
        return redirect(url_for("profile"))

    return render_template("profile/update_activity.html", user=user)

@app.route("/admin/employees")
def admin_employees():
    if "user_id" not in session:
        return redirect(url_for("login"))

    admin = User.query.get(session["user_id"])
    if admin.role != "admin":
        flash("Access denied.", "danger")
        return redirect(url_for("dashboard"))

    employees = User.query.filter(User.role != "admin").all()
    return render_template("admin/employees.html", employees=employees)


@app.route("/view_activities")
def view_activities():
    users = User.query.all()
    return render_template("view_activities.html", users=users)

@app.route("/my_tasks")
@login_required
def my_tasks():


    view = request.args.get("view", "list")
    user = current_user


    # tasks user can see
    if user.role == "admin":
        tasks = Task.query.order_by(Task.id.desc()).all()
    else:
        tasks = Task.query.filter_by(assignee_id=user.id).order_by(Task.id.desc()).all()

    # ================= FILES VIEW =================
    files = []
    if view == "files":
       

        for t in tasks:
            folder = f"frontend/static/uploads/task_{t.id}"
            if os.path.exists(folder):
                for f in os.listdir(folder):
                    files.append({
                        "task_id": t.id,
                        "task_title": t.title,
                        "filename": f,
                        "url": f"/static/uploads/task_{t.id}/{f}"
                    })

        return render_template(
            "tasks/task_files.html",
            user=user,
            tasks=tasks,
            files=files
        )

    # ================= LIST / BOARD / CALENDAR =================
    grouped = {
        "recently_assigned": [],
        "do_today": [],
        "do_next_week": [],
        "do_later": [],
    }

    for t in tasks:
        if t.section in grouped:
            grouped[t.section].append(t)

    calendar_tasks = [
        {"title": t.title, "date": t.due_date.strftime("%Y-%m-%d")}
        for t in tasks if t.due_date
    ]

    return render_template(
        "tasks/my_tasks_page.html",
        view=view,
        grouped=grouped,
        tasks=tasks,
        user=user,
        files=files,
        calendar_tasks=calendar_tasks,
        get_pill_color=get_pill_color
    )

@app.route("/tasks/files/upload", methods=["POST"])
@login_required
def upload_task_file():


    task_id = request.form.get("task_id")
    file = request.files.get("file")

    if not task_id or not file:
        return ("Bad request", 400)

    folder = f"frontend/static/uploads/task_{task_id}"
    os.makedirs(folder, exist_ok=True)

    filename = secure_filename(file.filename)
    file.save(os.path.join(folder, filename))

    return ("OK", 204)  

 
@app.route("/my_tasks/add_task", methods=["POST"])
def add_task_from_my_tasks():
    if "user_id" not in session:
        return jsonify({"error": "Not logged in"}), 403

    current_user = User.query.get(session["user_id"])
    data = request.get_json(force=True)

    # ✅ Handle inline project creation
    project_id = data.get("project_id")
    new_project_title = data.get("new_project_title")
    new_project_desc = data.get("new_project_desc")

    if not project_id and new_project_title:
        new_project = Project(
            title=new_project_title,
            description=new_project_desc,
            owner_id=current_user.id
        )
        db.session.add(new_project)
        db.session.commit()
        project_id = new_project.id

    if not project_id:
        return jsonify({"error": "Please select or create a project."}), 400

    # ✅ Handle Task fields
    title = data.get("title")
    description = data.get("description")
    assignee_id = data.get("assignee_id") or None
    priority = data.get("priority", "Medium")
    due_date_str = data.get("due_date")
    status = data.get("status", "todo")
    section = data.get("section") or "recently_assigned"

    from datetime import datetime
    due_date_str = data.get("due_date")
    due_date = None
    if due_date_str:
        try:
            due_date = datetime.strptime(due_date_str, "%Y-%m-%d").date()
        except:
            pass


    task = Task(
        title=title,
        description=description,
        project_id=int(project_id),
        assignee_id=int(assignee_id) if assignee_id else None,
        due_date=due_date,
        status=status,
        priority=priority,
        assigned_by_id=current_user.id,
        section=section
    )

    db.session.add(task)
    db.session.commit()

    return jsonify({"success": True, "task_id": task.id})

from flask import jsonify
from datetime import date



@app.route("/add_task", methods=["GET", "POST"])
@login_required
def add_task():
   
    user = current_user
    users = User.query.filter(User.role != "admin").all()
    projects = Project.query.all()

    if request.method == "POST":
        # --- Handle Project Selection or Creation ---
        project_id = request.form.get("project_id")
        new_project_title = request.form.get("new_project_title")
        new_project_desc = request.form.get("new_project_desc")

        # Create a new project if user typed one
        if not project_id and new_project_title:
            new_project = Project(
                title=new_project_title,
                description=new_project_desc,
                owner_id=current_user.id
            )
            db.session.add(new_project)
            db.session.commit()
            project_id = new_project.id

        # Validate project
        if not project_id:
            flash("⚠️ Please select or create a project before adding a task.", "danger")
            return redirect(url_for("add_task"))

        # --- Handle Task Details ---
        title = request.form.get("title")
        description = request.form.get("description")
        assignee_id = request.form.get("assignee_id")
        due_date_str = request.form.get("due_date")
        priority = request.form.get("priority", "Medium")
        status = request.form.get("status", "todo")
        section = request.form.get("section") or "recently_assigned"


        # Convert due date safely
        due_date = None
        if due_date_str:
            try:
                from datetime import datetime
                due_date = datetime.strptime(due_date_str, "%Y-%m-%d").date()
            except ValueError:
                flash("⚠️ Invalid date format.", "danger")
                return redirect(url_for("add_task"))

        # Role-based restrictions
        if current_user.role != "admin":
            # Employees can’t assign or change priority
            assignee_id = current_user.id
            priority = "Medium"

        # --- Create the Task ---
    

        task = Task(
            title=title,
            description=description,
            project_id=int(project_id),
            assignee_id=int(assignee_id) if assignee_id else None,
            due_date=due_date,
            status=status,
            priority=priority,
            assigned_by_id=current_user.id,
            section=section

        )
        db.session.add(task)
        db.session.commit()

        # --- Send Email Notifications (if assigned) ---
        if assignee_id:
            assignee = User.query.get(int(assignee_id))
            project = Project.query.get(int(project_id))
            if assignee and assignee.email:
                subject = f"New Task Assigned: {title}"
                body = f"""
                <p>Hi {assignee.name or 'there'},</p>
                <p>You’ve been assigned a new task in <b>{project.title}</b>.</p>
                <p><b>Task:</b> {title}</p>
                <p><b>Description:</b> {description or 'No description provided.'}</p>
                <p><b>Due Date:</b> {due_date or 'Not specified'}</p>
                <p><b>Priority:</b> {priority}</p>
                <br>
                <p>Login to your GearFlow dashboard to check your tasks.</p>
                <p style="color:#555;">- The GearFlow Team</p>
                """
                try:
                    send_email(assignee.email, subject, body)
                    print(f"📧 Email sent to {assignee.email}")
                except Exception as e:
                    print(f"❌ Failed to send email: {e}")

        flash("✅ Task added successfully!", "success")
        return redirect(url_for("my_tasks"))

    # --- Render Page ---
    return render_template(
        "tasks/create_task_from_my_tasks.html",
        projects=projects,
        users=users,
        current_user=current_user
    )


@app.route("/api/add_task", methods=["POST"])
@login_required
def add_task_api():
    """JSON-based endpoint for AJAX Add Task (My Tasks page)"""


    data = request.get_json()
    if not data:
        return jsonify({"success": False, "error": "Invalid JSON"}), 400

    title = data.get("title")
    description = data.get("description")
    project_id = data.get("project_id")
    new_project_title = data.get("new_project_title")
    new_project_desc = data.get("new_project_desc")
    assignee_id = data.get("assignee_id")
    due_date_str = data.get("due_date")
    priority = data.get("priority", "Medium")
    status = data.get("status", "todo")
    section = data.get("section") or "recently_assigned"

    current_user = current_user

    # 🆕 Create new project if needed
    if not project_id and new_project_title:
        new_project = Project(
            title=new_project_title,
            description=new_project_desc,
            owner_id=current_user.id
        )
        db.session.add(new_project)
        db.session.commit()
        project_id = new_project.id

    if not project_id:
        return jsonify({"success": False, "error": "Select or create a project."}), 400

    from datetime import datetime
    due_date = None
    if due_date_str:
        try:
            due_date = datetime.strptime(due_date_str, "%Y-%m-%d").date()
        except ValueError:
            return jsonify({"success": False, "error": "Invalid date format."}), 400
    
    task = Task(
        title=title,
        description=description,
        project_id=int(project_id),
        assignee_id=int(assignee_id) if assignee_id else None,
        due_date=due_date,
        status=status,
        priority=priority,
        assigned_by_id=current_user.id,
        section=section
    )
    db.session.add(task)
    db.session.commit()

    return jsonify({
        "success": True,
        "task": {
            "id": task.id,
            "title": task.title,
            "description": task.description,
            "due_date": task.due_date.strftime("%Y-%m-%d") if task.due_date else "",
            "priority": task.priority,
            "status": task.status
        }
    })


      

@app.route("/update_task/<int:task_id>", methods=["POST"])
def update_task(task_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    task = Task.query.get_or_404(task_id)
    user = User.query.get(session["user_id"])

    # permission check
    if user.role != "admin" and task.assignee_id != user.id:
        flash("You can only edit your assigned tasks.", "danger")
        return redirect(url_for("my_tasks"))

    # update fields every user may change
    task.title = request.form.get("title", task.title)
    task.description = request.form.get("description", task.description)
    task.status = request.form.get("status", task.status)

    # admin-only fields
    if user.role == "admin":
        task.assignee_id = request.form.get("assignee_id") or None

        due_date_str = request.form.get("due_date")
        if due_date_str:
            try:
                task.due_date = datetime.strptime(due_date_str, "%Y-%m-%d").date()
            except ValueError:
                flash("Invalid date format.", "danger")
                return redirect(url_for("my_tasks"))

        # IMPORTANT: update priority (was missing before)
        priority = request.form.get("priority")
        if priority:
            task.priority = priority

    db.session.commit()
    flash("Task updated successfully!", "success")
    return redirect(url_for("my_tasks"))


@app.route("/update_task_status/<int:task_id>", methods=["POST"])
def update_task_status(task_id):
    from flask import request, jsonify
    data = request.get_json()
    new_status = data.get("status")

    task = Task.query.get(task_id)
    if not task:
        return jsonify({"error": "Task not found"}), 404

    task.status = new_status
    db.session.commit()
    return jsonify({"message": "Status updated"}), 200

@app.route("/task/<int:task_id>/json")
def task_json(task_id):
    task = Task.query.get_or_404(task_id)
    return jsonify({
        "id": task.id,
        "title": task.title,
        "status": task.status,
        "due_date": task.due_date.strftime("%Y-%m-%d") if task.due_date else None,
        "description": task.description
    })
from flask import jsonify

@app.route("/tasks/<int:task_id>/move", methods=["POST"])
def move_task(task_id):
    if "user_id" not in session:
        return jsonify({"error": "unauthorized"}), 401

    data = request.get_json(force=True)
    new_status = data.get("status")
    if new_status not in ("todo", "in-progress", "done"):
        return jsonify({"error": "invalid status"}), 400

    task = db.session.get(Task, task_id)
    if not task:
        return jsonify({"error": "not found"}), 404

   

    task.status = new_status
    db.session.commit()
    return jsonify({"ok": True, "task_id": task.id, "status": task.status})


@app.route("/task/<int:task_id>/details")
def task_details(task_id):
    task = Task.query.get_or_404(task_id)
    assignee = None

    # Handle safely (no error if relationship missing)
    if hasattr(task, "assignee_id") and task.assignee_id:
        user = User.query.get(task.assignee_id)
        assignee = user.name if user and user.name else user.email if user else "Unassigned"
    else:
        assignee = "Unassigned"

    return jsonify({
        "id": task.id,
        "title": task.title,
        "assignee": assignee,
        "status": task.status or "Not set",
        "due_date": task.due_date.strftime("%Y-%m-%d") if task.due_date else "No due date",
        "description": task.description or "No description"
    })



# app.py

@app.route("/tasks/<int:task_id>/update", methods=["POST"])
def update_task_ajax(task_id):
    if "user_id" not in session:
        return jsonify({"error": "unauthorized"}), 401

    data = request.get_json(force=True)
    task = Task.query.get_or_404(task_id)

    if "title" in data:
        task.title = data["title"].strip()
    if "description" in data:
        task.description = data["description"].strip()
    if "status" in data and data["status"] in ("todo", "in-progress", "done"):
        task.status = data["status"]
    if "due_date" in data and data["due_date"]:
        try:
            task.due_date = datetime.strptime(data["due_date"], "%Y-%m-%d").date()
        except:
            return jsonify({"error": "invalid date"}), 400
    if "assignee_id" in data:
        task.assignee_id = int(data["assignee_id"]) if data["assignee_id"] else None
    # add priority handling
    if "priority" in data and data["priority"]:
        task.priority = data["priority"]

    db.session.commit()
    return jsonify({"ok": True})

@app.route("/delete_project/<int:project_id>", methods=["POST"])
def delete_project(project_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    project = Project.query.get_or_404(project_id)
    user = User.query.get(session["user_id"])

    # ✅ Only the owner or admin can delete
    if user.role != "admin" and project.owner_id != user.id:
        flash("You don't have permission to delete this project.", "danger")
        return redirect(url_for("projects"))

    # Delete all tasks related to this project
    Task.query.filter_by(project_id=project.id).delete()

    # Delete the project itself
    db.session.delete(project)
    db.session.commit()

    flash("Project deleted successfully!", "success")
    return ("", 204)  # empty response for JS fetch()


@app.route("/delete_task/<int:task_id>", methods=["POST"])
def delete_task(task_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    task = Task.query.get_or_404(task_id)
    user = User.query.get(session["user_id"])

    
    if user.role != "admin" and task.assignee_id != user.id:
        flash("You don't have permission to delete this task.", "danger")
        return redirect(url_for("my_tasks"))

    db.session.delete(task)
    db.session.commit()
    flash("Task deleted successfully!", "success")
    return ("", 204)  


@app.route("/tasks/create", methods=["GET", "POST"])
def create_task_from_my_tasks():
    if "user_id" not in session:
        return redirect(url_for("login"))

    current_user = User.query.get(session["user_id"])
    projects = Project.query.filter_by(owner_id=session["user_id"]).all()
    users = User.query.all()

    if request.method == "POST":
        # Step 1 — Select or create project
        project_id = request.form.get("project_id")
        new_project_title = request.form.get("new_project_title")
        new_project_desc = request.form.get("new_project_desc")

        if not project_id and new_project_title:
            new_project = Project(
                title=new_project_title,
                description=new_project_desc,
                owner_id=current_user.id
            )
            db.session.add(new_project)
            db.session.commit()
            project_id = new_project.id

        if not project_id:
            flash("⚠️ Please select or create a project before adding a task.", "danger")
            return redirect(url_for("create_task_from_my_tasks"))

        # Step 2 — Task Details
        title = request.form.get("title")
        description = request.form.get("description")
        assignee_id = request.form.get("assignee_id") or None
        due_date_str = request.form.get("due_date")
        priority = request.form.get("priority", "Medium")

        from datetime import datetime
        due_date = datetime.strptime(due_date_str, "%Y-%m-%d").date() if due_date_str else None

        # Step 3 — Create the task
        status = request.form.get("status", "todo")
        task = Task(
            title=title,
            description=description,
            project_id=int(project_id),
            assignee_id=int(assignee_id) if assignee_id else None,
            due_date=due_date,
            status=status,
            assigned_by_id=current_user.id,
            priority=priority
        )
        db.session.add(task)
        db.session.commit()

        flash("✅ Task created successfully!", "success")
        return redirect(url_for("my_tasks"))

    return render_template(
        "tasks/create_task_from_my_tasks.html",
        projects=projects,
        users=users,
        current_user=current_user
    )


@app.route("/create_task_from_board", methods=["POST"])
def create_task_from_board():
    if "user_id" not in session:
        return redirect(url_for("login"))

    title = request.form["title"]
    description = request.form.get("description")
    status = request.form.get("status")

    task = Task(
        title=title,
        description=description,
        status=status,
        assignee_id=session["user_id"]
    )
    db.session.add(task)
    db.session.commit()

    return redirect(url_for("my_tasks"))


@app.route("/get_task/<int:task_id>")
def get_task(task_id):
    task = Task.query.get(task_id)
    if not task:
        return jsonify({"error": "Task not found"}), 404

    return jsonify({
        "id": task.id,
        "title": task.title,
        "description": task.description,
        "assignee_id": task.assignee_id,
        "due_date": task.due_date.isoformat() if task.due_date else "",
        "status": task.status
    })

@app.route("/edit_task/<int:task_id>", methods=["GET", "POST"])
def edit_task(task_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    task = Task.query.get_or_404(task_id)
    user = User.query.get(session["user_id"])
    users = User.query.all()

    if request.method == "POST":
        task.title = request.form["title"]
        task.description = request.form["description"]
        task.assignee_id = request.form["assigned_to"]
        task.due_date = datetime.strptime(request.form["due_date"], "%Y-%m-%d").date()
        task.status = request.form["status"]

        db.session.commit()
        flash("Task updated successfully!", "success")
        return redirect(url_for("my_tasks"))

    return render_template("tasks/my_tasks.html", task=task, users=users, user=user)


@app.before_request
def load_unread_notifications():
    if "user_id" in session:
        # your logic here
        pass

@app.route("/")
@login_required
def index():
    return redirect(url_for("home"))




@app.route("/inbox", methods=["GET", "POST"])
def inbox():
    if not current_user.is_authenticated:
        return redirect(url_for("login"))

    if request.method == "POST":
        Notification.query.filter_by(user_id=current_user.id).delete()
        db.session.commit()
        return redirect(url_for("inbox"))

    section = request.args.get("section", "work")
    notifications = Notification.query.filter_by(
        user_id=current_user.id
    ).order_by(Notification.created_at.desc()).all()

    return render_template(
        "inbox/inbox.html",
        user=current_user,
        notifications=notifications,
        section=section
    )


@app.route("/upload-avatar", methods=["POST"])
@login_required
def upload_avatar():
    
    if "avatar" not in request.files:
        flash("No file uploaded.", "warning")
        return redirect(url_for("profile"))

    avatar = request.files["avatar"]
    if avatar.filename == "":
        flash("No file selected.", "warning")
        return redirect(url_for("profile"))

    filename = secure_filename(f"user_{current_user.id}_{int(time.time())}.png")
    upload_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    
    avatar.save(upload_path)

    # Resize
    try:
        img = Image.open(upload_path)
        img.thumbnail((512, 512))
        img.save(upload_path, format="PNG")
    except Exception:
        pass

    # Save URL
    current_user.avatar_url = url_for("static", filename=f"uploads/{filename}")
    db.session.commit()

    flash("Avatar updated!", "success")
    return redirect(url_for("profile"))

@app.route("/update_avatar", methods=["POST"])
@login_required
def update_avatar():
    file = request.files.get("avatar")
    if not file:
        return redirect(url_for("settings"))

    filename = secure_filename(file.filename)
    path = os.path.join("frontend/static/uploads", filename)
    file.save(path)

    current_user.avatar_url = url_for(
        "static", filename=f"uploads/{filename}"
    )
    db.session.commit()

    return redirect(url_for("settings"))


@app.route("/remove_avatar", methods=["POST"])
@login_required
def remove_avatar():
    current_user.avatar_url = None
    db.session.commit()
    return "", 204


def build_summary_email(user, title, subtitle, overdue, due_today, due_soon):
    html = render_template(
        "email/task_summary.html",
        title=title,
        subtitle=subtitle,
        overdue=overdue,
        due_today=due_today,
        due_soon=due_soon,
    )
    send_email(user.email, title, html)


def daily_summary():
    today = date.today()
    soon = today + timedelta(days=3)

    users = User.query.all()

    for user in users:
        tasks = Task.query.filter_by(assignee_id=user.id).all()

        overdue = [t for t in tasks if t.due_date and t.due_date < today and t.status != "Done"]
        due_today = [t for t in tasks if t.due_date == today]
        due_soon = [t for t in tasks if today < t.due_date <= soon]

        if not (overdue or due_today or due_soon):
            continue

        build_summary_email(
            user,
            title="Your daily task summary",
            subtitle="Here are your tasks for today",
            overdue=overdue,
            due_today=due_today,
            due_soon=due_soon,
        )


def weekly_summary():
    today = date.today()
    week_end = today + timedelta(days=7)

    users = User.query.all()

    for user in users:
        tasks = Task.query.filter_by(assignee_id=user.id).all()

        overdue = [t for t in tasks if t.due_date and t.due_date < today]
        due_this_week = [t for t in tasks if today <= t.due_date <= week_end]

        build_summary_email(
            user,
            "Weekly task summary",
            "Your task overview for the week",
            overdue=overdue,
            due_today=[],
            due_soon=due_this_week,
        )


def overdue_alerts():
    today = date.today()

    overdue_tasks = Task.query.filter(Task.due_date < today, Task.status != "Done").all()

    for task in overdue_tasks:
        assignee = User.query.get(task.assignee_id)
        if not assignee:
            continue

        html = render_template(
            "email/task_summary.html",
            title="Task overdue",
            subtitle="A task assigned to you is overdue",
            overdue=[task],
            due_today=[],
            due_soon=[],
        )

        send_email(assignee.email, "Task overdue", html)

def start_scheduler():
    scheduler = BackgroundScheduler()

    scheduler.add_job(daily_summary, "cron", hour=9, minute=0)
    scheduler.add_job(weekly_summary, "cron", day_of_week="mon", hour=9, minute=30)
    scheduler.add_job(overdue_alerts, "cron", hour=0, minute=1)

    scheduler.start()


start_scheduler()

@app.route("/settings")
@login_required
def settings():
    return render_template("profile/settings.html", user=current_user)


@app.route("/invite", methods=["GET", "POST"])
@login_required
def invite():
    if request.method == "POST":
        email = request.form.get("email")
        role = request.form.get("role")

        if not email:
            flash("Email is required", "error")
            return redirect(url_for("invite"))

        token = generate_invite_token({"email": email,"role": role})

        invite_link = url_for("accept_invite", token=token, _external=True)

        msg = Message(
            subject="You're invited to GearFlow",
            recipients=[email],
            body=f"""
Hi,

You’ve been invited to join ZaynLevi.

Click the link below to accept the invite:
{invite_link}

This link expires in 24 hours.

– ZaynLevi Team
"""
        )
        mail.send(msg)

        flash(f"Invite sent to {email}", "success")
        return redirect(url_for("invite"))

    return render_template("profile/invite.html", user=current_user)

@app.route("/accept-invite/<token>", methods=["GET", "POST"])
def accept_invite(token):
    data = confirm_invite_token(token)

    if not data:
        flash("Invite link is invalid or expired", "error")
        return redirect(url_for("login"))

    email = data["email"]
    role = data["role"]

    if request.method == "POST":
        name = request.form.get("name")
        password = request.form.get("password")

        if not name or not password:
            flash("All fields are required", "error")
            return redirect(request.url)

        if User.query.filter_by(email=email).first():
            flash("Account already exists. Please login.", "info")
            return redirect(url_for("login"))

        user = User(
            name=name,
            email=email,
            role=role
        )
        user.set_password(password)

        db.session.add(user)
        db.session.commit()

        flash("Welcome to ZaynLevi 🎉 Account created successfully.", "success")
        return redirect(url_for("login"))

    return render_template(
        "profile/accept_invite.html",
        email=email,
        role=role
    )

@app.route("/add_account")
@login_required
def add_account():
    return render_template("profile/add_account.html", user=current_user)

@app.route("/admin/overview")
@login_required
def admin_overview():
    if current_user.role != "admin":
        flash("Access denied.", "danger")
        return redirect(url_for("home"))

    # 🔹 Get selected employee from query params
    raw_user_id = request.args.get("user_id")
    selected_user_id = int(raw_user_id) if raw_user_id and raw_user_id.isdigit() else None
  

    # 🔹 Fetch all employees (non-admins)
    employees = User.query.filter(User.role != "admin").order_by(User.name).all()

    projects = Project.query.order_by(Project.created_at.desc()).all()
    project_data = []

    for project in projects:
        query = Task.query.filter_by(project_id=project.id)

        # 🔹 Apply employee filter if selected
        if selected_user_id:
            query = query.filter(Task.assignee_id == selected_user_id)

        tasks = query.all()

        if not tasks:
            continue  # hide projects with no visible tasks

        task_rows = []
        for task in tasks:
            assignee = None
            if task.assignee_id:
                user = User.query.get(task.assignee_id)
                assignee = user.name if user else "Unknown"

            task_rows.append({
                "title": task.title,
                "assignee": assignee or "Unassigned",
                "status": task.status or "todo",
                "priority": task.priority or "Medium",
                "due_date": task.due_date.strftime("%b %d, %Y") if task.due_date else "—"
            })

        project_data.append({
            "project": project,
            "tasks": task_rows
        })

    return render_template(
        "admin/admin_overview.html",
        projects=project_data,
        employees=employees,
        selected_user_id=selected_user_id
    )

def chat(room_id):

    room = ChatRoom.query.get_or_404(room_id)

    messages = (
        ChatMessage.query
        .filter_by(room_id=room_id)
        .order_by(ChatMessage.timestamp.asc())
        .all()
    )

    return render_template(
        "chat/chat_room.html",
        room=room,
        messages=messages
    )

from flask_socketio import join_room, leave_room, send

@socketio.on("join")
def handle_join(data):
    room_id = int(data.get("room"))

    join_room(str(room_id))

    member = ChatMember.query.filter_by(
        room_id=room_id,
        user_id=current_user.id
    ).first()

    if member:
        member.last_read_at = datetime.utcnow()
        db.session.commit()

@socketio.on("send_message")
def handle_send_message(data):
    room_id = str(data["room_id"])  # normalize to string
    user_id = current_user.id
    content = data["content"]

    # Save to DB
    msg = ChatMessage(room_id=int(room_id), user_id=user_id, content=content)
    db.session.add(msg)
    db.session.commit()

    emit(
        "receive_message",
        {
            "room_id": room_id,
            "user_id": user_id,
            "user_name": current_user.name,   # <-- 🔥 correct field
            "content": content,
            "timestamp": msg.timestamp.strftime("%H:%M"),
        },
        room=room_id,
        include_self=True
    )

@app.route('/chat')
@login_required
def chat_home():
    users = User.query.all()

    users_list = []
    for u in users:
        users_list.append({
            "id": u.id,
            "name": u.name,
            "email": u.email,
            "avatar_url": u.avatar_url
        })

    return render_template(
        "chat/chat_home.html",
        users=users_list,
        chats=[]
    )


@app.route("/chat/create", methods=["POST"])
@login_required
def chat_create():
    data = request.json

    room = ChatRoom(
        name=data.get("name"),
        type=data.get("type"),
        created_by=current_user.id,
        created_at=datetime.utcnow()
    )

    db.session.add(room)
    db.session.flush()

    # Add self
    db.session.add(ChatMember(room_id=room.id, user_id=current_user.id))

    # Add invited users
    for email in data.get("members", []):
        email = email.strip()
        if not email:
            continue
        user = User.query.filter_by(email=email).first()
        if user:
            db.session.add(ChatMember(room_id=room.id, user_id=user.id))

    db.session.commit()

    return jsonify(success=True)

@app.route("/chat/create_direct", methods=["POST"])
@login_required
def create_direct_chat():
    data = request.get_json()
    other_id = data.get("user_id")

    # check if chat already exists
    room = ChatRoom.query.filter_by(type="direct").join(ChatMember)\
        .filter(ChatMember.user_id.in_([current_user.id, other_id])).first()

    if not room:
        room = ChatRoom(
            name="Direct chat",
            type="direct",
            created_by=current_user.id
        )
        db.session.add(room)
        db.session.commit()

        db.session.add(ChatMember(room_id=room.id, user_id=current_user.id))
        db.session.add(ChatMember(room_id=room.id, user_id=other_id))
        db.session.commit()

    return jsonify(success=True, room_id=room.id)

@app.route("/users")
def get_users():
    users = User.query.all()
    return jsonify([{"id": u.id, "name": u.username} for u in users])

@app.route("/chat/create/dm", methods=["POST"])
@app.route("/chat/create_dm", methods=["POST"])
@login_required
def create_dm_chat():
    data = request.get_json()

    other_id = int(data.get("user_id"))

    room = ChatRoom.create_dm(current_user.id, other_id)

    return jsonify({"ok": True, "room_id": room.id})

@app.route("/chat/create/group", methods=["POST"])
@login_required
def create_group_chat():
    data = request.json
    name = data.get("name")
    members = data.get("members", [])

    room = ChatRoom.create_group(name, members, current_user.id)

    return jsonify({"room_id": room.id}), 201

@app.route("/chat/create/project", methods=["POST"])
@login_required
def create_project_chat():
    data = request.json
    project_id = data.get("project_id")
    members = data.get("members", [])

    room = ChatRoom.create_project_discussion(project_id, members)

    return jsonify({"room_id": room.id}), 201

@app.route("/chat/<int:room_id>")
@login_required
def open_chat(room_id):
    room = ChatRoom.query.get_or_404(room_id)

    # load members
    members = (
        db.session.query(User)
        .join(ChatMember, ChatMember.user_id == User.id)
        .filter(ChatMember.room_id == room_id)
        .all()
    )

    # load last 50 messages
    messages = (ChatMessage.query.filter_by(room_id=room_id).order_by(ChatMessage.timestamp).all())

    return render_template(
        "chat/chat_room.html",
        room=room,
        members=members,
        messages=messages
    )

@app.route("/chat/<int:room_id>/send", methods=["POST"])
@login_required
def send_chat_message(room_id):
    content = request.form.get("content")

    msg = ChatMessage(
        room_id=room_id,
        user_id=current_user.id,
        content=content
    )
    db.session.add(msg)
    db.session.commit()

    return redirect(f"/chat/{room_id}")

@app.route("/api/chat/<int:room_id>/messages")
@login_required
def get_messages(room_id):
    msgs = (
        ChatMessage.query
        .filter_by(room_id=room_id)
        .order_by(ChatMessage.timestamp)
        .all()
    )

    return jsonify([
        {
            "id": m.id,
            "content": m.content,
            "user_id": m.user_id,
            "user_name": m.user.name
        }
        for m in msgs
    ])

@app.route('/api/users')
def api_users():
    users = User.query.with_entities(User.id, User.name, User.email).all()
    return jsonify([
        {"id": u.id, "name": u.name, "email": u.email}
        for u in users
    ])


from datetime import datetime
from sqlalchemy import or_

@app.route("/api/chat/list")
@login_required
def api_chat_list():

    # get all rooms of supported types
    rooms = (
        ChatRoom.query
        .join(ChatMember, ChatMember.room_id == ChatRoom.id)
        .filter(ChatMember.user_id == current_user.id)
        .filter(ChatMember.user_id == current_user.id)
        .all()
    )

    result = []

    for r in rooms:

        # members
        members = (
            db.session.query(User)
            .join(ChatMember, ChatMember.user_id == User.id)
            .filter(ChatMember.room_id == r.id)
            .all()
        )

        # ---- DISPLAY NAME ----
        if r.type == "dm":
            other = [m for m in members if m.id != current_user.id]
            display_name = other[0].name if other else "Direct chat"
        else:
            if r.name and r.name.strip():
                display_name = r.name
            else:
                others = [m.name for m in members if m.id != current_user.id]
                display_name = ", ".join(others) or "Group chat"

        # ---- LAST MESSAGE ----
        last = (
            ChatMessage.query
            .filter_by(room_id=r.id)
            .order_by(ChatMessage.timestamp.desc())
            .first()
        )

        # ---- UNREAD (safe even if no ChatMember row) ----
        member = ChatMember.query.filter_by(
            room_id=r.id,
            user_id=current_user.id
        ).first()

        last_read = member.last_read_at if (member and member.last_read_at) else datetime.min

        unread = (
            ChatMessage.query
            .filter(ChatMessage.room_id == r.id)
            .filter(ChatMessage.timestamp > last_read)
            .filter(ChatMessage.user_id != current_user.id)
            .count()
        )

        result.append({
            "id": r.id,
            "name": display_name,
            "last": last.content if last else "",
            "unread": unread,
            "members": [u.name for u in members]
        })

    return jsonify(result)

@app.route("/api/chat/create", methods=["POST"])
@login_required
def api_chat_create():
    data = request.json

    # -------- DIRECT CHAT ----------
    if data["type"] == "dm":
        members = data.get("members", [])

        if not members:
            return jsonify({"error": "No user selected"}), 400

        other_id = int(members[0])
        room = ChatRoom.create_dm(current_user.id, other_id)

        return jsonify({"ok": True, "room_id": room.id})

    # -------- GROUP CHAT ----------
    if data["type"] == "group":
        name = (data.get("name") or "").strip() or "New group"
        ids = list(map(int, data.get("members", [])))

        # creator auto-added & auto-admin
        room = ChatRoom.create_group(name, ids, current_user.id)

        return jsonify({"ok": True, "room_id": room.id})

    return jsonify({"error": "unknown type"}), 400

@app.route("/api/chat/<int:room_id>/read", methods=["POST"])
@login_required
def mark_chat_read(room_id):
    member = ChatMember.query.filter_by(
        room_id=room_id,
        user_id=current_user.id
    ).first()

    if member:
        member.last_read_at = datetime.utcnow()
        db.session.commit()

    return jsonify(ok=True)

@app.route("/api/chat/<int:room_id>/rename", methods=["POST"])
@login_required
def rename_group(room_id):
    data = request.json
    new_name = data.get("name", "").strip()

    room = ChatRoom.query.get_or_404(room_id)

    if room.type != "group":
        return jsonify(error="Only groups can be renamed"), 400

    if not is_admin(room_id, current_user.id):
        return jsonify(error="Admins only"), 403

    room.name = new_name
    db.session.commit()

    return jsonify(ok=True)



@app.route("/api/chat/<int:room_id>/members")
@login_required
def get_members(room_id):

    members = (
        db.session.query(ChatMember, User)
        .join(User, ChatMember.user_id == User.id, isouter=True)
        .filter(ChatMember.room_id == room_id)
        .all()
    )

    result = []
    for m, u in members:
        if not u:
            continue

        result.append({
            "id": u.id,
            "name": u.name,
            "is_admin": m.is_admin
        })

    return jsonify(result)

@app.route("/api/chat/<int:room_id>/members", methods=["POST"])
@login_required
def add_member(room_id):

    room = ChatRoom.query.get_or_404(room_id)

    # ✅ correct: only admins can add members
    if not is_admin(room_id, current_user.id):
        return jsonify({"error": "Admins only"}), 403

    # ✅ correct: only group chats
    if room.type != "group":
        return jsonify({"error": "Not a group"}), 400

    data = request.get_json()

    try:
        user_id = int(data.get("user_id"))
    except:
        return jsonify({"error": "user_id must be integer id"}), 400

    # ✅ correct: block duplicate members
    exists = ChatMember.query.filter_by(
        room_id=room_id,
        user_id=user_id
    ).first()

    if exists:
        return jsonify({"message": "already member"}), 200

    # ✅ correct: default is not admin
    cm = ChatMember(
        room_id=room_id,
        user_id=user_id,
        last_read_at=datetime.utcnow(),
        is_admin=False
    )

    db.session.add(cm)
    db.session.commit()

    return jsonify({"message": "added"})

@app.route("/api/chat/<int:room_id>/members/<int:user_id>", methods=["DELETE"])
@login_required
def remove_member(room_id, user_id):

    me = ChatMember.query.filter_by(room_id=room_id, user_id=current_user.id).first()

    if not me:
        return jsonify({"error": "Not in group"}), 403

    removing_self = (current_user.id == user_id)

    # Only admins may remove others
    if not removing_self and not me.is_admin:
        return jsonify({"error": "Admins only"}), 403

    target = ChatMember.query.filter_by(room_id=room_id, user_id=user_id).first_or_404()

    # If last admin leaves → auto assign new admin
    if target.is_admin:
        admin_count = ChatMember.query.filter_by(room_id=room_id, is_admin=True).count()

        if admin_count == 1:
            new_admin = ChatMember.query.filter(
                ChatMember.room_id == room_id,
                ChatMember.user_id != user_id
            ).first()

            if new_admin:
                new_admin.is_admin = True

    db.session.delete(target)
    db.session.commit()

    return jsonify({"message": "removed"})

@app.route("/api/chat/<int:room_id>/members/<int:user_id>/make_admin", methods=["POST"])
@login_required
def make_admin(room_id, user_id):

    # only existing admin can promote
    if not is_admin(room_id, current_user.id):
        return jsonify({"error": "Admins only"}), 403

    member = ChatMember.query.filter_by(room_id=room_id, user_id=user_id).first()
    if not member:
        return jsonify({"error": "User not in room"}), 404

    member.is_admin = True
    db.session.commit()

    return jsonify({"message": "User promoted to admin"})

@app.route("/api/chat/<int:room_id>/members/<int:user_id>/remove_admin", methods=["POST"])
@login_required
def remove_admin(room_id, user_id):

    if not is_admin(room_id, current_user.id):
        return jsonify({"error": "Admins only"}), 403

    member = ChatMember.query.filter_by(room_id=room_id, user_id=user_id).first()
    if not member:
        return jsonify({"error": "User not in room"}), 404

    # prevent last admin removal
    if admin_count(room_id) == 1 and member.is_admin:
        return jsonify({"error": "Cannot remove last admin"}), 400

    member.is_admin = False
    db.session.commit()

    return jsonify({"message": "Admin removed"})

@app.route("/api/chat/<int:room_id>/leave", methods=["DELETE"])
@login_required
def leave_group(room_id):

    member = ChatMember.query.filter_by(room_id=room_id, user_id=current_user.id).first()

    if not member:
        return jsonify({"error": "Not in group"}), 404

    # last admin cannot leave
    if member.is_admin and admin_count(room_id) == 1:
        return jsonify({"error": "Last admin cannot leave group"}), 400

    db.session.delete(member)
    db.session.commit()

    return jsonify({"message": "You left the group"})

@app.route("/api/chat/<int:room_id>", methods=["DELETE"])
@login_required
def delete_group(room_id):

    room = ChatRoom.query.get_or_404(room_id)

    if room.type != "group":
        return jsonify({"error": "Only groups can be deleted"}), 400

    me = ChatMember.query.filter_by(room_id=room_id, user_id=current_user.id).first()

    if not me:
        return jsonify({"error": "Not in group"}), 403

    # Count admins
    admin_total = ChatMember.query.filter_by(room_id=room_id, is_admin=True).count()
    if admin_total == 0:
        first_member = ChatMember.query.filter_by(room_id=room_id).first()
        if first_member:
            first_member.is_admin = True
            db.session.commit()
        admin_total = 1  

    if admin_total > 0 and not me.is_admin:
        return jsonify({"error": "Admins only can delete while admins exist"}), 403

    # delete messages
    ChatMessage.query.filter_by(room_id=room_id).delete()

    # delete members
    ChatMember.query.filter_by(room_id=room_id).delete()

    # delete room
    db.session.delete(room)
    db.session.commit()

    return jsonify({"message": "Group deleted"})

def is_admin(room_id, user_id):
    member = ChatMember.query.filter_by(room_id=room_id, user_id=user_id).first()
    return member and member.is_admin

def admin_count(room_id):
    return ChatMember.query.filter_by(room_id=room_id, is_admin=True).count()

@app.route("/api/reminders", methods=["GET"])
@login_required
def get_reminders():
    reminders = Reminder.query.filter_by(
        user_id=current_user.id,
        done=False
    ).order_by(Reminder.remind_at).all()

    return jsonify([{
        "id": r.id,
        "text": r.text,
        "remind_at": r.remind_at.isoformat()
    } for r in reminders])

@app.route("/api/reminders", methods=["POST"])
@login_required
def create_reminder():
    data = request.json

    r = Reminder(
        user_id=current_user.id,
        text=data["text"],
        remind_at=datetime.fromisoformat(data["remind_at"])
    )
    db.session.add(r)
    db.session.commit()

    return jsonify({"status":"ok"})


@app.route("/api/reminders/<int:id>", methods=["DELETE"])
@login_required
def delete_reminder(id):
    r = Reminder.query.get(id)
    if r and r.user_id == current_user.id:
        db.session.delete(r)
        db.session.commit()
    return jsonify({"success": True})

@app.route("/cockpit")
@login_required
def cockpit():
    return render_template("cockpit.html")



from datetime import datetime, timedelta
from flask_login import login_required, current_user

@app.route("/subscriptions")
@login_required
def subscriptions():
    return render_template(
        "subscriptions.html",
        user=current_user
    )

@app.route("/upgrade", methods=["POST"])
@login_required
def upgrade_plan():
    current_user.is_pro = True
    current_user.plan = "pro"
    current_user.sub_expiry = datetime.utcnow() + timedelta(days=30)
    db.session.commit()
    return redirect("/subscriptions")


@app.route("/downgrade", methods=["POST"])
@login_required
def downgrade_plan():
    current_user.is_pro = False
    current_user.plan = "free"
    current_user.sub_expiry = None
    db.session.commit()
    return redirect("/subscriptions")

from functools import wraps

def pro_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not current_user.is_pro:
            flash("Upgrade to PRO to access this!", "danger")
            return redirect("/subscriptions")
        return f(*args, **kwargs)
    return wrapper

@app.route("/advanced-dashboard")
@pro_required
def advanced_dashboard():
    return "Only PRO users here"

@app.before_request
def check_subscription():
    if current_user.is_authenticated and current_user.is_pro:
        if current_user.sub_expiry and current_user.sub_expiry < datetime.utcnow():
            current_user.is_pro = False
            current_user.plan = "free"
            db.session.commit()

if __name__ == "__main__":
    socketio.run(app, host="127.0.0.1", port=5002, debug=True)
