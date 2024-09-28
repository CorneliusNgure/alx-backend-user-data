#!/usr/bin/env python3
"""DB module
"""
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.session import Session
from user import Base, User
import logging
from sqlalchemy.exc import NoResultFound, InvalidRequestError

logging.disable(logging.WARNING)


class DB:
    """DB class
    This class handles database operations using SQLAlchemy.
    """

    def __init__(self) -> None:
        """Initialize a new DB instance
        Creates the database engine and initializes the session.
        """
        self._engine = create_engine("sqlite:///a.db", echo=True)
        # Drop all tables (for development/testing)
        Base.metadata.drop_all(self._engine)
        Base.metadata.create_all(self._engine)  # Create all tables
        self.__session = None

    @property
    def _session(self) -> Session:
        """Memoized session object
        Returns the current session, creating it if it doesn't exist.
        """
        if self.__session is None:
            DBSession = sessionmaker(bind=self._engine)
            self.__session = DBSession()
        return self.__session

    def add_user(self, email: str, hashed_password: str) -> User:
        """Add a user to the database.

        Args:
            email (str): The user's email address.
            hashed_password (str): The user's hashed password.

        Returns:
            User: The created User object.
        """
        new_user = User(email=email, hashed_password=hashed_password)

        self._session.add(new_user)
        self._session.commit()

        return new_user

    def find_user_by(self, **kwargs) -> User:
        """Find a user by arbitrary keyword arguments.

        Args:
            **kwargs: Arbitrary keyword arguments to filter the user query.

        Returns:
            User: The first User object matching the criteria.

        Raises:
            NoResultFound: If no user matches the criteria.
            InvalidRequestError: If invalid query arguments are passed.
        """
        # Check if all passed kwargs correspond to valid
        # attributes of the User model
        for key in kwargs:
            if not hasattr(User, key):
                raise InvalidRequestError(f"Invalid attribute: {key}")

        # Query the database to find the first user matching the filters
        user = self._session.query(User).filter_by(**kwargs).one()

        if user is None:
            raise NoResultFound()

        return user

    def update_user(self, user_id: int, **kwargs) -> None:
        """
        Update a user's attributes based on provided keyword arguments.

        Args:
            user_id (int): The ID of the user to update.
            **kwargs: Keyword args representing the attributes to update.

        Raises:
            ValueError: If an attribute that doesn't exist.
        
        Return:
            User instance found
        """
        user = self.find_user_by(id=user_id)

        for key, value in kwargs.items():
            if not hasattr(user, key):
                raise ValueError(f"User has no attribute '{key}'")

            setattr(user, key, value)

        self._session.commit()
