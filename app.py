
from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)
app.secret_key = "os.sowmya3399"

# SQLite database in instance folder
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Define User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(200))
    name = db.Column(db.String(100))
    phone = db.Column(db.String(20))
    bio = db.Column(db.String(500))

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


if __name__ == "__main__":
    # Run Flask on port 5002 to avoid macOS port conflicts
    app.run(debug=True, port=5002)
