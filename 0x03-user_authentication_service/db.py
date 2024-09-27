"""DB module
"""
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.session import Session
from user import Base, User
import logging

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

        # Return the created User object
        return new_user
