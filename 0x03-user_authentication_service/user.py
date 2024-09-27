#!/usr/bin/env python3

"""
This module defines the User model for a SQLAlchemy application.
The User model represents the 'users' table in the database.
"""

from sqlalchemy import Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()


class User(Base):
    """
    User model representing the 'users' table in the database.

    Attributes:
        id (int): The primary key of the user.
        email (str): The user's email address (non-nullable).
        hashed_password (str): The user's hashed password (non-nullable).
        session_id (str | None): The session ID of the user (nullable).
        reset_token (str | None): The password reset token (nullable).
    """

    __tablename__ = 'users'

    id: int = Column(Integer, primary_key=True)
    email: str = Column(String(250), nullable=False)
    hashed_password: str = Column(String(250), nullable=False)
    session_id: str | None = Column(String(250), nullable=True)
    reset_token: str | None = Column(String(250), nullable=True)
