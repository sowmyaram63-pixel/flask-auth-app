
from .extensions import db
from datetime import datetime

class User(db.Model):
    __tablename__ = "user"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200))
    phone = db.Column(db.String(20))
    bio = db.Column(db.Text)
    avatar_url = db.Column(db.String(300))
    role = db.Column(db.String(20), default="employee") 
    recent_activity = db.Column(db.String(255))  # small description
    priority = db.Column(db.String(20), default="Medium")
    

    # Relationships
   

    notifications = db.relationship("Notification", backref="user", lazy=True)

    def __repr__(self):
        return f"<User {self.email}>"
    
class Connection(db.Model):
    __tablename__ = "connection"

    id = db.Column(db.Integer, primary_key=True)
    from_user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    to_user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    status = db.Column(db.String(20), default="pending")

    def __repr__(self):
        return f"<Connection {self.from_user_id} -> {self.to_user_id} ({self.status})>"


class Project(db.Model):
    __tablename__ = "project"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text)
    owner_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    

    def __repr__(self):
        return f"<Project {self.title}>"
    

class Task(db.Model):
    __tablename__ = "task"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text)
    status = db.Column(db.String(50), default="todo")
    due_date = db.Column(db.Date)

    # ✅ Assignee
    assignee_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    assignee = db.relationship("User", foreign_keys=[assignee_id], backref="assigned_tasks")

    # ✅ Assigned by (the person who created/assigned)
    assigned_by_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    assigned_by = db.relationship("User", foreign_keys=[assigned_by_id], backref="created_tasks")

    project_id = db.Column(db.Integer, db.ForeignKey("project.id"))
    project = db.relationship("Project", backref="tasks")

    priority = db.Column(db.String(20), default="Medium") 
   
    def __repr__(self):
        return f"<Task {self.title} ({self.status}) - Priority: {self.priority}>"


class Notification(db.Model):
    __tablename__ = "notification"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    message = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<Notification {self.user_id}: {self.message[:20]}...>"