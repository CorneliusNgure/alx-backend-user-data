#!/usr/bin/env python3
"""
Auth class child class module
"""
from api.v1.auth.auth import Auth
import base64
from typing import TypeVar, Optional
from models.user import User


class BasicAuth(Auth):
    """Inheriting from Auth class"""
    def extract_base64_authorization_header(
            self, authorization_header: str) -> str:
        """Extracts the Base64 part of the Authorization header

        Args:
            authorization_header (str): The Authorization header

        Returns:
            str: The Base64 encoded part after 'Basic ' or
            None if conditions aren't met
        """
        if authorization_header is None:
            return None
        if not isinstance(authorization_header, str):
            return None
        if not authorization_header.startswith("Basic "):
            return None
        return authorization_header[len("Basic "):]

    def decode_base64_authorization_header(
            self, base64_authorization_header: str) -> str:
        """Decodes a Base64 string

        Args:
            base64_authorization_header (str): Base64 encoded string

        Returns:
            str: Decoded value as UTF-8 string or None if decoding fails
        """
        if base64_authorization_header is None:
            return None
        if not isinstance(base64_authorization_header, str):
            return None
        try:
            decoded_bytes = base64.b64decode(base64_authorization_header)
            return decoded_bytes.decode('utf-8')
        except (base64.binascii.Error, UnicodeDecodeError):
            return None

    def extract_user_credentials(
            self, decoded_base64_authorization_header: str) -> (str, str):
        """Extracts user email and password from decoded Base64 string

        Args:
            decoded_base64_authorization_header (str): Decoded Base64 string

        Returns:
            (str, str): Tuple containing email & password, or (None, None)
        """
        if decoded_base64_authorization_header is None:
            return None, None
        if not isinstance(decoded_base64_authorization_header, str):
            return None, None
        if ':' not in decoded_base64_authorization_header:
            return None, None

        # Split the string into email and password
        user_email, password = decoded_base64_authorization_header.split(
                ':', 1)
        return user_email, password

    def user_object_from_credentials(
            self, user_email: str, user_pwd: str) -> Optional[
                    TypeVar('User')]:
        """
        Returns a User instance based on their email and password.

        Args:
            user_email (str): The email of the user.
            user_pwd (str): The password of the user.

        Returns:
            User instance if the credentials are valid, otherwise None.
        """
        # Check if email and password are valid
        if not user_email or not isinstance(user_email, str):
            return None
        if not user_pwd or not isinstance(user_pwd, str):
            return None

        # Search for user by email
        user = User.search({'email': user_email})
        if not user or len(user) == 0:
            return None  # No user found

        # User is expected to be in a list, get the first instance
        user = user[0]

        if not user.is_valid_password(user_pwd):
            return None

        return user
