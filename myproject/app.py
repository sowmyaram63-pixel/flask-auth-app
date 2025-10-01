
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, g
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from authlib.integrations.flask_client import OAuth
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail as SendGridMail
from datetime import datetime
from werkzeug.utils import secure_filename
import secrets, os, random, time
from flask import url_for

# Import extensions
from extensions import db, mail, migrate
# Import models AFTER db is ready
from models import User, Connection, Project, Task, Notification

load_dotenv()   # reads .env


app = Flask(__name__)
def send_email(to_email, subject, body):
    message = SendGridMail(   # use aliased SendGrid class
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

# Profile picture uploads
UPLOAD_SUBFOLDER = "uploads"
UPLOAD_FOLDER = os.path.join(app.static_folder, UPLOAD_SUBFOLDER)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

        
app.secret_key = os.getenv("SECRET_KEY", "dev-secret-change-me")
# SQLite database in instance folder
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DATABASE_URL", "sqlite:///users.db")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# Mail config (for OTP via Gmail SMTP)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')


db.init_app(app)
mail.init_app(app)
migrate.init_app(app, db)


# Import models AFTER db is initialized
from models import User, Connection, Project, Task, Notification


# OAuth config (Google Sign-In)
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={'scope': 'openid email profile'},
)


def add_notification(user_id, message):
    notif = Notification(user_id=user_id, message=message)
    db.session.add(notif)
    db.session.commit()

# Make sure database tables are created within app context
with app.app_context():
    db.create_all()

# Routes
@app.route("/")
def home():
    return render_template("index.html")

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
        return redirect(url_for("login"))
    return render_template("auth/signup.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            session["user_id"] = user.id
            return redirect(url_for("profile"))
        return render_template("auth/login.html",error="Invalid credentials")
    return render_template("auth/login.html",)



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
    session.clear()
    return redirect(url_for("login"))

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

@app.route("/login/google")
def google_login():
    nonce = secrets.token_urlsafe(16)
    session["nonce"] = nonce  
    redirect_uri = url_for("google_authorize", _external=True)
    return google.authorize_redirect(redirect_uri, nonce=nonce)

@app.route("/login/google/authorized")
def google_authorize():
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

    my_projects = Project.query.filter_by(owner_id=session["user_id"]).all()
    return render_template("projects/projects.html", projects=my_projects)


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


@app.route("/projects/<int:project_id>")
def project_detail(project_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    project = Project.query.get_or_404(project_id)
    tasks = Task.query.filter_by(project_id=project.id).all()
    return render_template("projects/project_detail.html", project=project, tasks=tasks)


# -----------------------
# Task Routes
# -----------------------

from datetime import datetime


@app.route("/my_tasks", methods=["GET", "POST"])
def my_tasks():
    if "user_id" not in session:
        return redirect(url_for("login"))

    view = request.args.get("view", "list")
    tasks = Task.query.filter_by(assignee_id=session["user_id"]).all()
    users = User.query.all()

    return render_template("tasks/my_tasks.html", tasks=tasks, users=users, view=view)


@app.route("/create_task", methods=["POST"])
def create_task():
    title = request.form["title"]
    description = request.form["description"]
    due_date_str = request.form["due_date"]
    project_id = request.form["project_id"]
    status = request.form["status"]

    # ✅ Convert string -> Python date
    due_date = datetime.strptime(due_date_str, "%Y-%m-%d").date()

    new_task = Task(
        title=title,
        description=description,
        due_date=due_date,   # ✅ now it's a proper date object
        project_id=project_id,
        status=status,
        assignee_id=session.get("user_id")
    )

    db.session.add(new_task)
    db.session.commit()

    return redirect(url_for("my_tasks"))





@app.route("/tasks/<int:task_id>/update", methods=["GET", "POST"])
@app.route('/tasks/<int:task_id>/update', methods=['POST'])
def update_task(task_id):
    data = request.get_json()
    task = Task.query.get_or_404(task_id)

    if "title" in data:
        task.title = data["title"]
    if "description" in data:
        task.description = data["description"]
    if "status" in data:
        task.status = data["status"]
    if "due_date" in data:
        from datetime import datetime
        try:
            task.due_date = datetime.strptime(data["due_date"], "%Y-%m-%d").date()
        except:
            pass  

    db.session.commit()
    return jsonify({
        "success": True,
        "id": task.id,
        "title": task.title,
        "description": task.description,
        "status": task.status,
        "due_date": task.due_date.strftime("%Y-%m-%d") if task.due_date else None
    })

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

    # optional: check permission
    # if task.assignee_id != session["user_id"]:
    #     return jsonify({"error":"forbidden"}),403

    task.status = new_status
    db.session.commit()
    return jsonify({"ok": True, "task_id": task.id, "status": task.status})


@app.route("/task/<int:task_id>/details")
def task_details(task_id):
    task = Task.query.get_or_404(task_id)
    users = User.query.all()
    return jsonify({
        "id": task.id,
        "title": task.title,
        "assignee": {
            "id": task.assignee.id if task.assignee else None,
            "name": task.assignee.name if task.assignee else "Unassigned"
        },
        "status": task.status,
        "due_date": task.due_date.strftime("%Y-%m-%d") if task.due_date else None,
        "description": task.description or "",
        "users": [{"id": u.id, "name": u.name or u.email} for u in users]  # ✅ dropdown list
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


@app.route("/tasks/<int:task_id>/delete", methods=["POST"])
def delete_task(task_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    task = Task.query.get_or_404(task_id)

    # Only the assignee or project owner can delete
    project = Project.query.get(task.project_id)
    if task.assignee_id != session["user_id"] and project.owner_id != session["user_id"]:
        flash("You don't have permission to delete this task.", "error")
        return redirect(url_for("project_detail", project_id=task.project_id))

    db.session.delete(task)
    db.session.commit()
    flash("Task deleted successfully!", "success")
    return redirect(url_for("project_detail", project_id=task.project_id))


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

    # Create the task (not tied to project for now, can extend later)
    task = Task(
        title=title,
        description=description,
        status=status,
        assignee_id=session["user_id"]
    )
    db.session.add(task)
    db.session.commit()

    return redirect(url_for("my_tasks"))


@app.before_request
def load_unread_notifications():
    g.unread_count = 0
    if "user_id" in session:
        g.unread_count = Notification.query.filter_by(user_id=session["user_id"]).count()



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


