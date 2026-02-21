
# src/test_app.py
import pytest
from .app import app, db
from .models import User, Project, Task

@pytest.fixture
def client():
    """Set up a Flask test client and in-memory DB for isolated tests."""
    app.config["TESTING"] = True
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    app.config["WTF_CSRF_ENABLED"] = False
    app.config["LOGIN_DISABLED"] = True

    with app.app_context():
        db.create_all()
        yield app.test_client()
        db.session.remove()
        db.drop_all()


def test_home_page(client):
    """Basic test for the home route."""
    res = client.get("/")
    assert res.status_code == 200
    assert b"Login" in res.data or b"Signup" in res.data


def test_user_signup_and_login(client):
    """Test signing up and logging in a user."""
    # Signup
    res = client.post("/signup", data={
        "email": "test@example.com",
        "password": "password123"
    }, follow_redirects=True)
    assert res.status_code == 200

    # Check user exists in DB
    with app.app_context():
        user = User.query.filter_by(email="test@example.com").first()
        assert user is not None

    # Login
    res = client.post("/login", data={
        "email": "test@example.com",
        "password": "password123"
    }, follow_redirects=True)
    assert res.status_code == 200
    assert b"Logged in successfully" in res.data or b"Projects" in res.data


def test_project_creation(client):
    """Test creating a project after logging in."""
    with app.app_context():
        user = User(email="projuser@example.com", password="hashed_pw")
        db.session.add(user)
        db.session.commit()
        user_id = user.id

    with client.session_transaction() as sess:
        sess["user_id"] = user_id

    res = client.post("/projects/create", data={
        "title": "My Test Project",
        "description": "A sample project for testing"
    }, follow_redirects=True)
    assert res.status_code == 200

    with app.app_context():
        project = Project.query.filter_by(title="My Test Project").first()
        assert project is not None
        assert project.owner_id == user_id


def test_task_creation(client):
    """Test adding a task to a project."""
    with app.app_context():
        user = User(email="taskuser@example.com", password="pw")
        db.session.add(user)
        db.session.commit()

        project = Project(title="Task Project", owner_id=user.id)
        db.session.add(project)
        db.session.commit()

        user_id = user.id
        project_id = project.id

    with client.session_transaction() as sess:
        sess["user_id"] = user_id

    res = client.post(f"/projects/{project_id}/add_task", data={
        "title": "Test Task",
        "description": "Do something important",
        "assignee_id": str(user_id),
        "due_date": "2025-12-01"
    }, follow_redirects=True)
    assert res.status_code in (200, 302)

    with app.app_context():
        task = Task.query.filter_by(title="Test Task").first()
        assert task is not None
        assert task.project_id == project_id
        assert task.assignee_id == user_id
