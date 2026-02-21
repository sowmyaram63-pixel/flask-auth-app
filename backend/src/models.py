
from .extensions import db
from datetime import datetime
from flask_login import UserMixin


class User(db.Model, UserMixin):
    __tablename__ = "user"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200))
    phone = db.Column(db.String(20))
    bio = db.Column(db.Text)
    avatar_url = db.Column(db.String(200), default=None)
    role = db.Column(db.String(20), default="employee")
    recent_activity = db.Column(db.String(255))
    priority = db.Column(db.String(20), default="Medium")
    job_title = db.Column(db.String(120))
    team = db.Column(db.String(255))
    about_me = db.Column(db.Text)
    is_pro = db.Column(db.Boolean, default=False)
    plan = db.Column(db.String(50))
    subscription_id = db.Column(db.String(255))
    sub_expiry = db.Column(db.DateTime)

    def __repr__(self):
        return f"<User {self.email}>"

    @property
    def initials(self):
        if self.name:
            parts = self.name.strip().split()
            if len(parts) >= 2:
                return (parts[0][0] + parts[1][0]).upper()
            return parts[0][0].upper()
        return "?"

    @property
    def avatar_color(self):
        colors = ["#F7B2D9", "#A8D5FF", "#FFD6A5", "#C3F0CA", "#FFABAB"]
        return colors[self.id % len(colors)]


class Connection(db.Model):
    __tablename__ = "connection"

    id = db.Column(db.Integer, primary_key=True)
    from_user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    to_user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    status = db.Column(db.String(20), default="pending")

    def __repr__(self):
        return f"<Connection {self.from_user_id} -> {self.to_user_id}>"


class Project(db.Model):
    __tablename__ = "project"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text)
    owner_id = db.Column(db.Integer, db.ForeignKey("user.id"))
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
    section = db.Column(db.String(50), nullable=False, default="recently_assigned")


    def due_string(self):
        if not self.due_date:
            return ""
        return self.due_date.strftime("%b %d")

    
    assignee_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    assignee = db.relationship("User", foreign_keys=[assignee_id], backref="assigned_tasks")

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
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    message = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<Notification {self.user_id}: {self.message[:20]}...>"

def get_pill_color(name: str):
    """
    Return an (bg_color, text_color) tuple for a name — used to color avatar pills.
    Simple deterministic mapping similar to Asana's style.
    """
    colors = [
        ("#E5F4FF", "#0667C8"),  # Blue
        ("#E9F8F1", "#1A7F56"),  # Green
        ("#FFF4E5", "#C96F00"),  # Orange
        ("#F2E8FF", "#7A32D4"),  # Purple
        ("#FFEAF0", "#C61B5B"),  # Pink
        ("#E7F7F8", "#0C8A92"),  # Teal
    ]
    if not name:
        return colors[0]
    index = sum(ord(c) for c in str(name)) % len(colors)
    return colors[index]

def get_frequent_collaborators(user_id):
    user_tasks = Task.query.filter(
        (Task.assignee_id == user_id) | (Task.assigned_by_id == user_id)
    ).all()

    collab_ids = set()

    for t in user_tasks:
        if t.assignee_id and t.assignee_id != user_id:
            collab_ids.add(t.assignee_id)
        if t.assigned_by_id and t.assigned_by_id != user_id:
            collab_ids.add(t.assigned_by_id)

    return User.query.filter(User.id.in_(collab_ids)).all()

from datetime import datetime
from sqlalchemy import or_, and_


class ChatRoom(db.Model):
    __tablename__ = "chat_rooms"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255))
    type = db.Column(db.String(50))  # dm, group, project

    project_id = db.Column(db.Integer, db.ForeignKey('project.id'))
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    members = db.relationship("ChatMember", backref="room", cascade="all, delete-orphan")
    messages = db.relationship("ChatMessage", backref="room", cascade="all, delete-orphan")

    # --------------------------
    # CREATE DIRECT MESSAGE
    # --------------------------
    @classmethod
    def create_dm(cls, user1_id, user2_id):

        user1_id = int(user1_id)
        user2_id = int(user2_id)

        low = min(user1_id, user2_id)
        high = max(user1_id, user2_id)

        existing = (
            db.session.query(ChatRoom)
            .join(ChatMember)
            .filter(ChatRoom.type == "dm")
            .filter(
                ChatRoom.id.in_(
                    db.session.query(ChatMember.room_id)
                    .filter(ChatMember.user_id == low)
                )
            )
            .filter(
                ChatRoom.id.in_(
                    db.session.query(ChatMember.room_id)
                    .filter(ChatMember.user_id == high)
                )
            )
            .first()
        )
        if existing:
            return existing
        
        room = ChatRoom(type="dm", name=None)
        db.session.add(room)
        db.session.flush()

        db.session.add(ChatMember(room_id=room.id, user_id=low))
        db.session.add(ChatMember(room_id=room.id, user_id=high))

        db.session.commit()
        return room




    # --------------------------
    # CREATE GROUP CHAT
    # --------------------------
    @classmethod
    def create_group(cls, name, member_ids, creator_id):
        room = ChatRoom(
            type="group",
            name=name,
            created_by=creator_id
        )
        db.session.add(room)
        db.session.flush()

        creator = ChatMember(
            room_id=room.id,
            user_id=creator_id,
            is_admin=True
        )
        db.session.add(creator)

        all_members = set(member_ids + [creator_id])

        for uid in all_members:
            if uid == creator_id:
                continue
            db.session.add(ChatMember(room_id=room.id, user_id=uid,is_admin=False))

        db.session.commit()
        return room

    # --------------------------
    # CREATE PROJECT DISCUSSION
    # --------------------------
    @classmethod
    def create_project_discussion(cls, project_id, member_ids):
        room = ChatRoom(
            type="project",
            project_id=project_id,
            name=f"Project {project_id}"
        )
        db.session.add(room)
        db.session.flush()

        for uid in member_ids:
            db.session.add(ChatMember(room_id=room.id, user_id=uid))

        db.session.commit()
        return room


class ChatMember(db.Model):
    __tablename__ = "chat_members"

    id = db.Column(db.Integer, primary_key=True)
    room_id = db.Column(db.Integer, db.ForeignKey('chat_rooms.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    last_read_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_admin = db.Column(db.Boolean, default=False)
    user = db.relationship("User")



class ChatMessage(db.Model):
    __tablename__ = "chat_messages"

    id = db.Column(db.Integer, primary_key=True)
    room_id = db.Column(db.Integer, db.ForeignKey('chat_rooms.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship("User")

class Reminder(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    text = db.Column(db.String(255))
    remind_at = db.Column(db.DateTime)
    done = db.Column(db.Boolean, default=False)
