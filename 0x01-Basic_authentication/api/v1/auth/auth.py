#!/usr/bin/env python3
"""
Module for authentication
"""
from flask import request
from typing import List, TypeVar

User = TypeVar('User')


class Auth:
    """Class to manage API authentication"""

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """
        Determines if authentication is required for a given path.

        Args:
            path (str): The current request path.
            excluded_paths (List[str]): requires no authentication.

        Returns:
            bool: False.
        """
        return False

    def authorization_header(self, request=None) -> str:
        """
        Retrieves the Authorization header from the request object.

        Args:
            request: The Flask request object.

        Returns:
            str: None.
        """
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """
        Retrieves the current user from the request object.

        Args:
            request: The Flask request object.

        Returns:
            User: None.
        """
        return None
