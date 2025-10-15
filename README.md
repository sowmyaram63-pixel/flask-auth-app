# 🚀 Flask Auth App

A simple **full-stack Flask web application** with authentication and 
profile management.  
Built with **Flask, SQLAlchemy, SQLite, and Jinja2 templates**.  

---

## ✨ Features

- 👤 **User Authentication**
  - Sign up with email & password (hashed with `pbkdf2:sha256`)
  - Login & Logout with session management

- 📝 **Profile Management**
  - View profile (name, phone, bio, status)
  - Update profile (edit details or change password)
  - User status: `pending`, `accepted`, `rejected`

- 🔎 **Search Profiles**
  - Search users by email, name, or phone
  - Accept/Reject user profiles

- 📋 **All Profiles Dashboard**
  - View all profiles grouped by `accepted`, `rejected`, and `pending`

- 🎨 **Polished UI**
  - Responsive design with cards & buttons
  - Gradient navbar, hover effects, and status badges

---

## 📂 Project Structure

myproject/
│── instance/ # Local SQLite database (ignored in Git)
│ └── users.db
│
│── myproject/
│ └── app.py # Main Flask app
│
│── static/
│ └── style.css # CSS styling
│
│── templates/
│ ├── base.html # Base layout
│ ├── index.html # Home page
│ ├── auth/ # Authentication pages
│ │ ├── login.html
│ │ └── signup.html
│ └── profile/ # Profile-related pages
│ ├── profile.html
│ ├── updateprofile.html
│ ├── search.html
│ └── all_profiles.html
│
├── requirements.txt
└── README.md

yaml
Copy code

---

## ⚙️ Setup Instructions

### 1️⃣ Clone the Repository
```bash
git clone https://github.com/sowmyaram63-pixel/flask-auth-app.git
cd flask-auth-app
2️⃣ Create Virtual Environment (Recommended)
bash
Copy code
python3 -m venv venv
source venv/bin/activate   # Mac/Linux
venv\Scripts\activate      # Windows
3️⃣ Install Dependencies
bash
Copy code
pip install -r requirements.txt
4️⃣ Initialize Database
bash
Copy code
cd myproject/myproject
python3 app.py
This will auto-create instance/users.db with the required tables.

🛠 Optional: To reset the DB, delete instance/users.db and restart app.py.

5️⃣ Run the Application
bash
Copy code
python3 app.py
By default, the app runs on:
👉 http://127.0.0.1:5002

🧑‍💻 Usage
Go to /signup → create a new account.

Log in at /login.
View & edit profile at /profile.

Search other users at /search.

Manage all users at /all_profiles.

