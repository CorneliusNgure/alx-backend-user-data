#!/usr/bin/env python3
"""Passowrd hashing"""

import bcrypt


def _hash_password(password: str) -> bytes:
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
