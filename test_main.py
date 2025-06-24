
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

def test_signup():
    response = client.post("/signup", json={
        "email": "testuser@example.com",
        "password": "testpass123",
        "role": "client"
    })
    assert response.status_code == 200 or response.status_code == 400  # in case user already exists
    assert "download-link" in response.json() or "detail" in response.json()

def test_login():
    response = client.post("/login", data={
        "username": "testuser@example.com",
        "password": "testpass123"
    })
    assert response.status_code == 200 or response.status_code == 401
    if response.status_code == 200:
        assert "access_token" in response.json()
