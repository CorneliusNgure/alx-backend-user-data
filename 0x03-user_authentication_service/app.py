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


@app.route("/profile", methods=["GET"])
def profile():
    """
    GET /profile route to fetch a user's profile based on session_id.

    Expects:
    - session_id as a cookie

    Returns:
    - JSON with the user's email and 200 status code if session is valid
    - 403 status code if session is invalid or user not found
    """
    # Get the session_id from cookies
    session_id = request.cookies.get("session_id")

    # If no session_id is found, respond with 403
    if not session_id:
        abort(403)

    # Retrieve the user using the session_id
    user = AUTH.get_user_from_session_id(session_id)

    # If user is not found, respond with 403
    if not user:
        abort(403)

    # Return the user's email in a JSON payload with 200 status code
    return jsonify({"email": user.email}), 200


@app.route("/reset_password", methods=["POST"])
def get_reset_password_token():
    """
    POST /reset_password route to generate a reset password token.

    Expects:
    - email: form data (str)

    Returns:
    - 200: JSON with email and reset token
    - 403: if the email is not registered
    """
    email = request.form.get("email")

    if not email:
        return jsonify({"message": "Email is required"}), 400

    try:
        # Generate the reset token using the Auth method
        reset_token = AUTH.get_reset_password_token(email)
        return jsonify({"email": email, "reset_token": reset_token}), 200
    except ValueError:
        # If the email is not found, return 403
        return abort(403)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
