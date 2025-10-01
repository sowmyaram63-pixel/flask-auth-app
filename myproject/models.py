
from extensions import db

class User(db.Model):
    __tablename__ = "user"   # table name

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    name = db.Column(db.String(100))
    phone = db.Column(db.String(20))
    bio = db.Column(db.Text)
    avatar_url = db.Column(db.String(255))  # new column for profile pictures
    def to_dict(self):
        return {
            "id": self.id,
            "email": self.email,
            "name": self.name,
            "phone": self.phone,
            "bio": self.bio,
            "avatar_url": self.avatar_url
        }
class Connection(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    from_user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    to_user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    status = db.Column(db.String(20))  # 'pending', 'accepted', 'rejected'

class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text)
    owner_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    created_at = db.Column(db.DateTime, default=db.func.now())

    tasks = db.relationship("Task", backref="project", lazy=True)


class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(50), default="todo")
    due_date = db.Column(db.Date, nullable=True)

    project_id = db.Column(db.Integer, db.ForeignKey("project.id"), nullable=False)
    assignee_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)

    # ✅ Add relationship so you can use task.assignee
    assignee = db.relationship("User", backref="tasks", lazy=True)

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    message = db.Column(db.String(255), nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=db.func.now())

    user = db.relationship("User", backref="notifications")
