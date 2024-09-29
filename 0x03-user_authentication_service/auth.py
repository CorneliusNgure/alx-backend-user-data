#!/usr/bin/env python3
"""Passowrd hashing"""

import bcrypt
from db import DB
from sqlalchemy.orm.exc import NoResultFound
from user import User
from uuid import uuid4
from typing import Union, Optional


class Auth:
    """Auth class to interact with authorization database"""

    def __init__(self):
        self._db = DB()

    def _hash_password(self, password: str) -> bytes:
        """
        Hash a password using bcrypt and return the salted hash.

        Args:
            password (str): The password to hash.

        Returns:
            bytes: The salted hashed password.
        """
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed_password

    def register_user(self, email: str, password: str) -> User:
        """
        Register a user with an email and password.

        Args:
            email (str): The user's email.
            password (str): The user's password.

        Returns:
            User: The created user object.

        Raises:
            ValueError: If a user with the email already exists.
        """
        try:
            # check if the user exists
            self._db.find_user_by(email=email)
        except NoResultFound:
            # hash the password and create a new user if none exists
            hashed_password = self._hash_password(password)
            new_user = self._db.add_user(email, hashed_password)
            return new_user
        else:
            raise ValueError(f"User {email} already exists")

    def valid_login(self, email: str, password: str) -> bool:
        """
        Validate a user's login credentials.

        Args:
            email (str): The user's email.
            password (str): The user's password.

        Returns:
            bool: True if login is valid, False otherwise.
        """
        try:
            # Locate the user by email
            user = self._db.find_user_by(email=email)
            # Check if the password matches the stored hashed password
            if bcrypt.checkpw(password.encode('utf-8'), user.hashed_password):
                return True
        except NoResultFound:
            # If no user found, return False
            return False

        # If password does not match, return False
        return False

    def _generate_uuid(self) -> str:
        """
        Generate a new UUID and return it as a string.

        Returns:
            str: A string representation of a newly generated UUID.
        """
        return str(uuid4())

    def create_session(self, email: str) -> str:
        """Create a session for a user by storing their session ID.

        Args:
            email (str): The user's email.

        Returns:
            str: The session ID.
        """
        try:
            # Find the user by email
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            return None
        else:
            # Generate a new session ID
            session_id = self._generate_uuid()
            return session_id

    def get_user_from_session_id(
            self, session_id: Optional[str]) -> Optional[User]:
        """
        Retrieve a user by their session_id.

        Args:
            session_id (str): The session ID to search for.

        Returns:
            User or None: The user associated with the session_id,
            or None if not found or session_id is None.
        """
        if session_id is None:
            return None

        try:
            user = self._db.find_user_by(session_id=session_id)
            return user
        except NoResultFound:
            return None

    def destroy_session(self, user_id: int) -> None:
        """
        Destroy a user's session by setting their session_id to None.

        Args:
            user_id (int): User's ID.

        Returns:
            None
        """
        try:
            # Find the user by their user_id
            user = self._db.find_user_by(id=user_id)
            # Set the session_id to None (destroy the session)
            self._db.update_user(user, session_id=None)
        except NoResultFound:
            # Handle case where user does not exist.
            pass

    def get_reset_password_token(self, email: str) -> str:
        """
        Generate a password reset token for a user.

        Args:
            email (str): The user's email.

        Returns:
            str: The reset token.

        Raises:
            ValueError: If the user does not exist.
        """
        try:
            # Find the user by email
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            # Raise an error if no user is found with the given email
            raise ValueError(f"User with email {email} does not exist")

        # Generate a new UUID token for password reset
        reset_token = str(uuid4())

        # Update the user's reset_token in the database
        self._db.update_user(user.id, reset_token=reset_token)

        # Return the generated reset token
        return reset_token

    def update_password(self, reset_token: str, password: str) -> None:
        """
        Updates the user's password based on the reset token.

        Args:
        - reset_token: The token used to identify the user (str)
        - password: The new password (str)

        Returns: None

        Raises:
        - ValueError if no user is found with the given reset_token
        """
        # Find the user by reset_token
        user = self._db.find_user_by(reset_token=reset_token)

        # If no user is found, raise ValueError
        if user is None:
            raise ValueError("Invalid reset token")

        # Hash the new password
        hashed_password = bcrypt.hashpw(password.encode(
            'utf-8'), bcrypt.gensalt())

        # Update user's password and reset_token fields
        self._db.update_user(
                user.id, hashed_password=hashed_password, reset_token=None)
