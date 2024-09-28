#!/usr/bin/env python3
from flask import Flask, jsonify, request, abort
from auth import Auth

app = Flask(__name__)

AUTH = Auth()


@app.route("/", methods=["GET"])
def home():
    """Returns a message in JSON format."""
    return jsonify({"message": "Bienvenue"})


@app.route("/users", methods=["POST"])
def register_user():
    """
    POST /users route to register a new user.

    Expects:
    - email: form data (str)
    - password: form data (str)

    Returns:
    - JSON with email and message on successful registration
    - JSON with error message and 400 status code if user already exists
    """
    email = request.form.get("email")
    password = request.form.get("password")

    if not email or not password:
        return jsonify({"message": "Email and password are required"}), 400

    try:
        user = AUTH.register_user(email, password)
        return jsonify({"email": user.email, "message": "user created"}), 201
    except ValueError:
        return jsonify({"message": "email already registered"}), 400


@app.route("/sessions", methods=["POST"])
def login():
    """
    POST /sessions route to log in a user.

    Expects:
    - email: form data (str)
    - password: form data (str)

    Returns:
    - JSON with email and message on successful login
    - 401 status if login information is incorrect
    """
    email = request.form.get("email")
    password = request.form.get("password")

    if not email or not password:
        abort(401)  # missing credentials

    if AUTH.valid_login(email, password):
        session_id = AUTH.create_session(email)
        response = jsonify({"email": email, "message": "logged in"})
        # set session ID as a cookie
        response.set_cookie("session_id", session_id)
        return response, 200
    else:
        abort(401)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
