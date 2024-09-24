#!/usr/bin/env python3
"""
Auth class child class module
"""
from api.v1.auth.auth import Auth


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
