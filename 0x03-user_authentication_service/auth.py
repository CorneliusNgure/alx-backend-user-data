#!/usr/bin/env python3
"""Passowrd hashing"""

import bcrypt
from db import DB
from sqlalchemy.orm.exc import NoResultFound
from user import User
from uuid import uuid4


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
            pass
