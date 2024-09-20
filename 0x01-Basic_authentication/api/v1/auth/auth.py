#!/usr/bin/env python3
"""
Module for authentication
"""
from flask import request
from typing import List, TypeVar, Optional

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
            bool: True if path requires authentication,
                otherwise false.
        """
        if path is None:
            return True

        if not excluded_paths or len(excluded_paths) == 0:
            return True

        if not path.endswith('/'):
            path += '/'

        if path in excluded_paths:
            return False

        return True

    def authorization_header(self, request=None) -> Optional[str]:
        """
        Retrieves the Authorization header from the request object.

        Args:
            request: The Flask request object.

        Returns:
            str: The value of the Authorization header,
                or None if the header is not present,
                or request is None.
        """
        if request is None:
            return None
        return request.headers.get('Authorization', None)

    def current_user(self, request=None) -> TypeVar('User'):
        """
        Retrieves the current user from the request object.

        Args:
            request: The Flask request object.

        Returns:
            User: None.
        """
        return None


class BasicAuth(Auth):
    """Child class of Auth class"""
    pass
