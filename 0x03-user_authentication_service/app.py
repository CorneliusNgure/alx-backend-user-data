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


@app.route("/sessions", methods=["DELETE"])
def logout():
    """
    DELETE /sessions route to log out the user by destroying their session.

    Expects:
    - session_id as a cookie

    Returns:
    - Redirect to home page on successful logout
    - 403 status code if no valid session exists
    """
    # Retrieve the session_id from cookies
    session_id = request.cookies.get("session_id")

    # If session_id is not found, or if there's no user,
    # abort with 403
    if not session_id:
        abort(403)

    user = AUTH.get_user_from_session_id(session_id)

    # If no user is found with the given session_id, abort with 403
    if user is None:
        abort(403)

    # Destroy the session
    AUTH.destroy_session(user.id)

    # Prepare the response to redirect the user to the home page
    response = redirect('/')
    # Remove the session_id cookie
    response.delete_cookie("session_id")

    return response


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
