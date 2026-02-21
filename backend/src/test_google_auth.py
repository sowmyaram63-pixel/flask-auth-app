
import pytest
from unittest.mock import patch, MagicMock
from app import app, db, User

@pytest.fixture
def client():
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    with app.test_client() as client:
        with app.app_context():
            db.create_all()
        yield client
        with app.app_context():
            db.drop_all()

@patch("src.app.google.get")
@patch("src.app.google.authorize_access_token")
def test_google_login_flow(mock_authorize, mock_get, client):
    # Mock Google token exchange
    mock_authorize.return_value = {"access_token": "fake-token"}

    # Mock userinfo API response
    mock_get.return_value = MagicMock()
    mock_get.return_value.json.return_value = {
        "email": "testuser@example.com",
        "name": "Test User",
        "picture": "https://example.com/avatar.jpg"
    }

    response = client.get("/login/google/authorized", follow_redirects=True)

    # ✅ Verify redirect and session behavior
    assert response.status_code == 200
    assert b"Welcome Test User!" in response.data

    # ✅ Verify user added to DB
    with app.app_context():
        user = User.query.filter_by(email="testuser@example.com").first()
        assert user is not None
        assert user.name == "Test User"
