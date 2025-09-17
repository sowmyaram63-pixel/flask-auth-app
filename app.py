
from flask import Flask, render_template, request, redirect, url_for, flash,session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import text
from sqlalchemy import or_
from dotenv import load_dotenv
from authlib.integrations.flask_client import OAuth
from flask_mail import Mail, Message
from flask import redirect, url_for, session
from authlib.integrations.flask_client import OAuth
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
import secrets
import os,random, time

load_dotenv()   # reads .env



app = Flask(__name__)
def send_email(to_email, subject, body):
    message = Mail(
        from_email=os.getenv("MAIL_FROM_EMAIL"),
        to_emails=to_email,
        subject=subject,
        html_content=body
    )
    try:
        sg = SendGridAPIClient(os.getenv("SENDGRID_API_KEY"))
        response = sg.send(message)
        print(response.status_code)
        print(response.body)
        print(response.headers)
    except Exception as e:
        print(f"SendGrid error: {e}")
        
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

db = SQLAlchemy(app)
mail = Mail(app)

# OAuth config (Google Sign-In)
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={'scope': 'openid email profile'},
)


# Define User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(200))
    name = db.Column(db.String(100))
    phone = db.Column(db.String(20))
    bio = db.Column(db.String(500))
   
    def to_dict(self):
        return {
            'id': self.id,
            'email': self.email,
            'name': self.name,
            'phone': self.phone,
            'bio': self.bio
        }

class Connection(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    from_user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    to_user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    status = db.Column(db.String(20))  # 'pending', 'accepted', 'rejected'



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
        user.name = request.form["name"]
        user.phone = request.form["phone"]
        user.bio = request.form["bio"]

        # update password only if provided
        if request.form["password"]:
            user.password = generate_password_hash(request.form["password"], method="pbkdf2:sha256")

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
        email = request.form.get("email")

        # check if user exists
        user = User.query.filter_by(email=email).first()
        if not user:
            flash("❌ Email not registered.", "danger")
            return redirect(url_for("forgot_password"))

        # generate OTP
        import random
        otp = str(random.randint(100000, 999999))

        # save OTP in session (you can also store in DB if needed)
        session["reset_email"] = email
        session["reset_otp"] = otp

        # send OTP via SendGrid
        subject = "Password Reset OTP"
        body = f"""
        <p>Hello,</p>
        <p>Your OTP for password reset is:</p>
        <h2>{otp}</h2>
        <p>This OTP is valid for 10 minutes.</p>
        """
        send_email(email, subject, body)

        flash("✅ OTP sent to your email.", "success")
        return redirect(url_for("verify_otp"))

    return render_template("auth/forgot.html")
    
@app.route("/verify_otp", methods=["GET", "POST"])
def verify_otp():
    if request.method == "POST":
        otp_entered = request.form.get("otp")

        if otp_entered == session.get("reset_otp"):
            flash("✅ OTP verified. Please reset your password.", "success")
            return redirect(url_for("reset_password"))
        else:
            flash("❌ Invalid OTP. Try again.", "danger")

    return render_template("auth/verify.html")

@app.route("/reset_password", methods=["GET", "POST"])
def reset_password():
    if request.method == "POST":
        if not session.get("reset_verified"):
            return redirect(url_for("forgot_password"))

        new_pw = request.form["password"]
        email = session.get("reset_email")
        user = User.query.filter_by(email=email).first()
        if user:
            user.password = generate_password_hash(new_pw, method="pbkdf2:sha256")
            db.session.commit()

        # clear reset session vars
        session.pop("reset_email", None)
        session.pop("reset_otp", None)
        session.pop("reset_otp_expiry", None)
        session.pop("reset_verified", None)

        return redirect(url_for("login"))
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


if __name__ == "__main__":
    # Run Flask on port 5002 to avoid macOS port conflicts
    app.run(debug=True, port=5002)

