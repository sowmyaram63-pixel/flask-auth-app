
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from authlib.integrations.flask_client import OAuth
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail as SendGridMail
from datetime import datetime
from werkzeug.utils import secure_filename
from flask_session import Session
from src.extensions import db, mail, migrate
from src.models import User, Connection, Project, Task, Notification
from dotenv import load_dotenv
from werkzeug.middleware.proxy_fix import ProxyFix
import secrets, os, random, time


# -------------------------------
# Load environment
# -------------------------------
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
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
    REDIRECT_URI = f"https://{os.environ.get('RAILWAY_STATIC_URL')}/login/google/authorized"
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
    template_folder=os.path.join(PROJECT_ROOT, 'templates'),
    static_folder=os.path.join(PROJECT_ROOT, 'static')
)

app.secret_key = SECRET_KEY
# Detect environment
on_railway = os.getenv("RAILWAY_ENVIRONMENT") is not None

if on_railway:
    # ✅ Use Railway Postgres
    app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL").replace("postgres://", "postgresql://")
else:
    # ✅ Use local SQLite
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:////Users/sowmya/GearFlow/myproject/clean_app/instance/users.db"
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
Session(app)

# -------------------------------
# Uploads config
# -------------------------------
UPLOAD_SUBFOLDER = "uploads"
UPLOAD_FOLDER = os.path.join(app.static_folder, UPLOAD_SUBFOLDER)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# -------------------------------
# Mail config (SendGrid)
# -------------------------------
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
mail.init_app(app)

def send_email(to_email, subject, body):
    message = SendGridMail(
        from_email=os.getenv("MAIL_FROM_EMAIL"),
        to_emails=to_email,
        subject=subject,
        html_content=body
    )
    try:
        sg = SendGridAPIClient(os.getenv("SENDGRID_API_KEY"))
        response = sg.send(message)
        print("SendGrid status:", response.status_code)
        print("SendGrid body:", response.body)
        print(response.headers)
    except Exception as e:
        print(f"SendGrid error: {e}")

# -------------------------------
# DB init
# -------------------------------
db.init_app(app)
migrate.init_app(app, db)

with app.app_context():
    db.create_all()

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
@app.route("/login/google")
def google_login():
    return google.authorize_redirect(REDIRECT_URI)

@app.route("/login/google/authorized")
def google_authorized():
    try:
        token = google.authorize_access_token()
        resp = google.get('https://www.googleapis.com/oauth2/v3/userinfo')  # full URL!
        userinfo = resp.json()

        email = userinfo.get("email")
        name = userinfo.get("name")
        picture = userinfo.get("picture")

        if not email:
            flash("Google login failed: No email returned.", "danger")
            return redirect(url_for("email_login"))

        user = User.query.filter_by(email=email).first()
        if not user:
            user = User(name=name, email=email, avatar_url=picture)
            db.session.add(user)
            db.session.commit()

        session["user_id"] = user.id
        session["user_email"] = email
        session["user_name"] = name
        session["user_picture"] = picture

        flash(f"Welcome {name}!", "success")
        return redirect(url_for("projects"))

    except Exception as e:
        app.logger.error(f"❌ Google OAuth callback error: {e}")
        flash("Something went wrong during Google login.", "danger")
        return redirect(url_for("email_login"))


@app.route("/")
def home():
    if 'google_id' not in session:
        return redirect(url_for('google_login'))  # or your login route name
    return render_template('index.html')

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

@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect(url_for("login"))

    user = session["user"]
    return f"""
        <h1>Welcome, {user['name']}!</h1>
        <img src="{user['picture']}" alt="Profile Picture" width="100" height="100">
        <p>Email: {user['email']}</p>
        <a href="/logout">Logout</a>
    """


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        email = request.form["email"]
        password = generate_password_hash(request.form["password"], method="pbkdf2:sha256")

        if User.query.filter_by(email=email).first():
            return render_template("auth/signup.html", error="User already exists")
        user = User(email=email, password=password)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for("email_login"))
    return render_template("auth/signup.html")


# --- Normal Email Login ---
@app.route("/login", methods=["GET", "POST"])
def email_login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            session["user_id"] = user.id
            flash("Logged in successfully!", "success")
            return redirect(url_for("projects"))
        else:
            flash("Invalid email or password.", "danger")
            return render_template("auth/login.html")

    return render_template("auth/login.html")

@app.route("/profile")
def profile():

    if "user_id" in session:
        user = db.session.get(User, session["user_id"])
        return render_template("profile/profile.html", user=user)
    return redirect(url_for("login"))


@app.route("/update_profile", methods=["GET", "POST"])
def update_profile():
    if "user_id" not in session:
        return redirect(url_for("login"))

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
    session.clear()  # clears all session data including google_oauth_state
    flash("Logged out successfully!", "info")
    return redirect(url_for("email_login"))



@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form["email"]
        user = User.query.filter_by(email=email).first()
        if not user:
            return render_template("auth/forgot.html", error="No account found with that email")

        # Generate OTP and expiry
        otp = f"{random.randint(100000, 999999)}"
        expiry = int(time.time()) + 300  # valid 5 minutes

        # Store in session
        session["reset_email"] = email
        session["reset_otp"] = otp
        session["reset_otp_expiry"] = expiry

        # Send OTP via SendGrid
        try:
            message = Mail(
                from_email=os.getenv("MAIL_FROM_EMAIL"),
                to_emails=email,
                subject="Your OTP for password reset",
                plain_text_content=f"Your OTP is {otp}. It is valid for 5 minutes."
            )
            sg = SendGridAPIClient(os.getenv("SENDGRID_API_KEY"))
            sg.send(message)
        except Exception as e:
            print("SendGrid Error:", e)
            return render_template("auth/forgot.html", error="Could not send OTP. Try again later.")

        return redirect(url_for("verify_otp"))

    return render_template("auth/forgot.html")


    
@app.route("/verify_otp", methods=["GET", "POST"])
def verify_otp():
    if request.method == "POST":
        otp = request.form["otp"]
        stored = session.get("reset_otp")
        expiry = session.get("reset_otp_expiry", 0)

        if not stored or int(time.time()) > expiry:
            session.pop("reset_otp", None)
            session.pop("reset_otp_expiry", None)
            return render_template("auth/verify.html", error="OTP expired. Try again.")

        if otp == stored:
            session["reset_verified"] = True
            return redirect(url_for("reset_password"))

        return render_template("auth/verify.html", error="Invalid OTP")

    return render_template("auth/verify.html")

@app.route("/reset_password", methods=["GET", "POST"])
def reset_password():
    # Only allow if OTP was verified
    if not session.get("reset_verified"):
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        password = request.form["password"]
        confirm = request.form["confirm"]

        if password != confirm:
            return render_template("auth/reset.html", error="Passwords do not match")

        email = session.get("reset_email")
        if not email:
            return redirect(url_for("forgot_password"))

        user = User.query.filter_by(email=email).first()
        if not user:
            return redirect(url_for("forgot_password"))

        # Hash password before saving
        from werkzeug.security import generate_password_hash
        user.password = generate_password_hash(password)
        db.session.commit()

        # Cleanup session
        session.pop("reset_email", None)
        session.pop("reset_otp", None)
        session.pop("reset_otp_expiry", None)
        session.pop("reset_verified", None)

        return redirect(url_for("login"))  # or wherever you want

    return render_template("auth/reset.html")


@app.route("/search", methods=["GET", "POST"])
def search():
    if "user_id" not in session:
        return redirect(url_for("login"))

    query = request.form.get("query", "")
    
    results = []
    
    if query:
        results = User.query.filter(User.name.ilike(f"%{query}%"), User.id != session["user_id"]).all()

    return render_template("search.html", users=results)
           
@app.route("/connect/<int:user_id>/<action>")
def connect(user_id, action):
    if "user_id" not in session:
        return redirect(url_for("login"))

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
def all_profiles():
    if "user_id" not in session:
        return redirect(url_for("login"))

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


    token = google.authorize_access_token()
    nonce = session.pop("nonce", None)
    user_info = google.parse_id_token(token, nonce=nonce)

    email = user_info.get("email")
    name = user_info.get("name")

    # Check if user already exists
    user = User.query.filter_by(email=email).first()
    if not user:
        # Create new user if first Google login
        user = User(email=email, name=name, password="")
        db.session.add(user)
        db.session.commit()

    # Store user_id in session (so /profile works)
    session["user_id"] = user.id
    session["user_email"] = email
    session["user_name"] = name

    return redirect(url_for("profile"))

# -----------------------
# Project Routes
# -----------------------
@app.route("/projects")
def projects():
    if "user_id" not in session:
        return redirect(url_for("login"))

    user = User.query.get(session["user_id"])
    my_projects = Project.query.filter_by(owner_id=user.id).all()

    return render_template("projects/projects.html", projects=my_projects, user=user)


@app.route("/projects/create", methods=["GET", "POST"])
def create_project():
    if "user_id" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        title = request.form["title"]
        description = request.form.get("description")

        project = Project(title=title, description=description, owner_id=session["user_id"])
        db.session.add(project)
        db.session.commit()
        add_notification(session["user_id"], f"Project '{title}' created successfully!")
        return redirect(url_for("projects"))

    return render_template("projects/create_project.html")

@app.route("/projects/<int:project_id>/tasks_panel")
def project_tasks_panel(project_id):
    if "user_id" not in session:
        return jsonify({"error": "unauthorized"}), 401

    project = Project.query.get_or_404(project_id)
    tasks = Task.query.filter_by(project_id=project.id).all()
    users = User.query.all()

    # Return an HTML snippet to insert dynamically
    return render_template("tasks/project_tasks_panel.html", project=project, tasks=tasks, users=users)

@app.route("/projects/<int:project_id>")
def project_detail(project_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    user = User.query.get(session["user_id"])         
    project = Project.query.get_or_404(project_id)
    tasks = Task.query.filter_by(project_id=project.id).all()
    users = User.query.all()                          

    return render_template(
        "projects/project_detail.html",
        user=user,                                    
        project=project,
        tasks=tasks,
        users=users
    )


@app.route("/projects/<int:project_id>/add_task", methods=["GET", "POST"])
def add_task_to_project(project_id):
    if "user_id" not in session:
        return jsonify({"error": "Not logged in"}), 403

    project = Project.query.get_or_404(project_id)
    users = User.query.all()

    if request.method == "POST":
        title = request.form.get("title")
        description = request.form.get("description")
        assignee_id = request.form.get("assignee_id")or None
        due_date_str = request.form.get("due_date")

        from datetime import datetime
        due_date = datetime.strptime(due_date_str, "%Y-%m-%d").date() if due_date_str else None

        task = Task(
            title=title,
            description=description,
            project_id=project.id,
            assignee_id=assignee_id if assignee_id else None,
            due_date=due_date,
            status="todo"
        )
        db.session.add(task)
        db.session.commit()

        return jsonify({
          "task": {
            "id": task.id,
            "title": task.title,
            "description": task.description,
            "assignee": task.assignee.name if task.assignee else "Unassigned",
            "project": project.title
        }
    })


# -----------------------
# Task Routes
# -----------------------

from datetime import datetime


@app.route("/my_tasks")
def my_tasks():
    if "user_id" not in session:
        return redirect(url_for("login"))

    user = User.query.get(session["user_id"])
    if not user:
        flash("User not found")
        return redirect(url_for("login"))

    if user.role == "admin":
        tasks = Task.query.all()
    else:
        tasks = Task.query.filter_by(assignee_id=user.id).all()

    users = User.query.all()
    return render_template("tasks/my_tasks.html", user=user, tasks=tasks, users=users)


from flask import jsonify




@app.route("/add_task", methods=["POST"])
def add_task():
    if "user_id" not in session:
        return jsonify({"error": "Not logged in"}), 403

    title = request.form.get("title")
    description = request.form.get("description")
    assignee_id = request.form.get("assignee_id")
   

    due_date = request.form.get("due_date")

    new_task = Task(
        title=title,
        description=description,
        assignee_id=assignee_id if assignee_id else None,
        due_date=datetime.strptime(due_date, "%Y-%m-%d").date() if due_date else None,
        status="todo",
        assigned_by_id =session["user_id"]
    )

    db.session.add(new_task)
    db.session.commit()

    assignee_name = new_task.assignee.name if new_task.assignee else "Unassigned"

    return jsonify({
        "task": {
            "id": new_task.id,
            "title": new_task.title,
            "description": new_task.description,
            "assignee": assignee_name
        }
    })



@app.route("/update_task/<int:task_id>", methods=["POST"])
def update_task(task_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    task = Task.query.get_or_404(task_id)
    user = User.query.get(session["user_id"])

    
    if user.role != "admin" and task.assignee_id != user.id:
        flash("You can only edit your assigned tasks.", "danger")
        return redirect(url_for("my_tasks"))

    task.title = request.form.get("title", task.title)
    task.description = request.form.get("description", task.description)
    task.status = request.form.get("status", task.status)

   
    if user.role == "admin":
        task.assignee_id = request.form.get("assignee_id") or None
        due_date_str = request.form.get("due_date")
        if due_date_str:
            task.due_date = datetime.strptime(due_date_str, "%Y-%m-%d").date()

    db.session.commit()
    flash("Task updated successfully!", "success")
    return redirect(url_for("my_tasks"))



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

    projects = Project.query.filter_by(owner_id=session["user_id"]).all()
    if not projects:
        flash("You need to create a project before adding tasks!", "danger")
        return redirect(url_for("projects"))

    if request.method == "POST":
        title = request.form["title"]
        description = request.form.get("description")
        due_date = request.form.get("due_date")
        project_id = request.form["project_id"]

        task = Task(
            title=title,
            description=description,
            project_id=project_id,
            assignee_id=session["user_id"],
            due_date=due_date

        )
        db.session.add(task)
        db.session.commit()
        return redirect(url_for("my_tasks"))

    return render_template("tasks/create_task_from_my_tasks.html", projects=projects)

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
    


@app.route("/inbox", methods=["GET", "POST"])
def inbox():
    if "user_id" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        Notification.query.filter_by(user_id=session["user_id"]).delete()
        db.session.commit()
        return redirect(url_for("inbox"))

    notifications = Notification.query.filter_by(user_id=session["user_id"]).order_by(Notification.created_at.desc()).all()
    return render_template("inbox/inbox.html", notifications=notifications)




if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5002, debug=True)


