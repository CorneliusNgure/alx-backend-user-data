#!/usr/bin/env python3
import requests

BASE_URL = "http://127.0.0.1:5000"

def register_user(email: str, password: str) -> None:
    """Registers a user with the provided email and password."""
    url = f"{BASE_URL}/users"
    data = {"email": email, "password": password}
    response = requests.post(url, data=data)
    assert response.status_code == 201, (
        f"Failed to register user. Status code: {response.status_code}"
    )
    payload = response.json()
    assert payload["email"] == email, "Email mismatch after registration"
    assert payload["message"] == "user created", (
        "Incorrect message after registration"
    )

def log_in_wrong_password(email: str, password: str) -> None:
    """Attempts to log in with an incorrect password."""
    url = f"{BASE_URL}/sessions"
    data = {"email": email, "password": password}
    response = requests.post(url, data=data)
    assert response.status_code == 401, (
        f"Expected 401 for wrong password. Got: {response.status_code}"
    )

def log_in(email: str, password: str) -> str:
    """Logs in with correct credentials and returns session ID."""
    url = f"{BASE_URL}/sessions"
    data = {"email": email, "password": password}
    response = requests.post(url, data=data)
    assert response.status_code == 200, (
        f"Failed to log in. Status code: {response.status_code}"
    )
    payload = response.json()
    assert payload["email"] == email, "Email mismatch after login"
    assert payload["message"] == "logged in", "Incorrect message after login"
    return response.cookies.get("session_id")

def profile_unlogged() -> None:
    """Checks profile access without being logged in."""
    url = f"{BASE_URL}/profile"
    response = requests.get(url)
    assert response.status_code == 403, (
        f"Expected 403 for unlogged profile access. Got: {response.status_code}"
    )

def profile_logged(session_id: str) -> None:
    """Checks profile access with a valid session ID."""
    url = f"{BASE_URL}/profile"
    cookies = {"session_id": session_id}
    response = requests.get(url, cookies=cookies)
    assert response.status_code == 200, (
        f"Failed to access profile with valid session. Status code: "
        f"{response.status_code}"
    )
    payload = response.json()
    assert "email" in payload, "No email in profile response"

def log_out(session_id: str) -> None:
    """Logs out the user."""
    url = f"{BASE_URL}/sessions"
    cookies = {"session_id": session_id}
    response = requests.delete(url, cookies=cookies)
    assert response.status_code == 302, (
        f"Failed to log out. Status code: {response.status_code}"
    )

def reset_password_token(email: str) -> str:
    """Requests a password reset token for the given email."""
    url = f"{BASE_URL}/reset_password"
    data = {"email": email}
    response = requests.post(url, data=data)
    assert response.status_code == 200, (
        f"Failed to get reset token. Status code: {response.status_code}"
    )
    payload = response.json()
    assert payload["email"] == email, "Email mismatch in reset token"
    assert "reset_token" in payload, "No reset token in response"
    return payload["reset_token"]

def update_password(
    email: str, reset_token: str, new_password: str
) -> None:
    """Updates the user's password using the reset token."""
    url = f"{BASE_URL}/reset_password"
    data = {
        "email": email,
        "reset_token": reset_token,
        "new_password": new_password,
    }
    response = requests.put(url, data=data)
    assert response.status_code == 200, (
        f"Failed to update password. Status code: {response.status_code}"
    )
    payload = response.json()
    assert payload["email"] == email, "Email mismatch in password update"
    assert payload["message"] == "Password updated", (
        "Incorrect message after password update"
    )

# Constants for testing
EMAIL = "guillaume@holberton.io"
PASSWD = "b4l0u"
NEW_PASSWD = "t4rt1fl3tt3"

if __name__ == "__main__":
    register_user(EMAIL, PASSWD)
    log_in_wrong_password(EMAIL, NEW_PASSWD)
    profile_unlogged()
    session_id = log_in(EMAIL, PASSWD)
    profile_logged(session_id)
    log_out(session_id)
    reset_token = reset_password_token(EMAIL)
    update_password(EMAIL, reset_token, NEW_PASSWD)
    log_in(EMAIL, NEW_PASSWD)
