#!/usr/bin/env python3
"""Passowrd hashing"""

import bcrypt
from db import DB
from sqlalchemy.exc import NoResultFound
from user import User


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
            self._db.find_user_by(email=email)
        except NoResultFound:
            hashed_password = self._hash_password(password)
            new_user = self._db.add_user(email, hashed_password)
            return new_user
        else:
            raise ValueError(f"User {email} already exists")
