#!/usr/bin/env python3
"""
Auth class child class module
"""
from api.v1.auth.auth import Auth
import base64


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
