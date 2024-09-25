#!/usr/bin/env python3
"""
Module for authentication
"""
from flask import request
from typing import List, TypeVar, Optional
import fnmatch

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

    def require_auth(self, path: str, excluded_paths: list) -> bool:
        """
        Determines if a given path requires authentication
        based on excluded paths.

        Args:
            path (str): The request path.
            excluded_paths (list): A list of paths to exclude from
            authentication, supports wildcard (*).

        Returns:
            bool: True if the path requires authentication,
            False if it is excluded.
        """
        if path is None or excluded_paths is None or len(excluded_paths) == 0:
            return True

        # Normalize path by adding a trailing slash if not present
        if not path.endswith('/'):
            path += '/'

        # Loop through excluded paths and check if the path matches any,
        # including wildcards
        for excluded_path in excluded_paths:
            if fnmatch.fnmatch(path, excluded_path):
                return False

        return True
