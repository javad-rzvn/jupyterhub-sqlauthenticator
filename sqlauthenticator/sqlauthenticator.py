from jupyterhub.auth import Authenticator
from tornado import gen
import hashlib
import os
from contextlib import contextmanager
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker


@contextmanager
def db_session():
    """ 
        Creates a context with an open SQLAlchemy session.
    """
    SQLALCHEMY_DATABASE_URL = "mysql+mysqlconnector://%s:%s@%s:%s/%s" % (
        os.getenv('MYSQL_USER'),
        os.getenv('MYSQL_PASS'),
        os.getenv('MYSQL_HOST'),
        os.getenv('MYSQL_PORT'),
        os.getenv('MYSQL_DB'),
    )
    engine = create_engine(
        SQLALCHEMY_DATABASE_URL,
        pool_pre_ping=True,
        pool_recycle=3600,
        pool_timeout=3600,
        pool_size=5
    )
    connection = engine.connect()
    db_session = scoped_session(sessionmaker(autocommit=False, autoflush=True, bind=engine))
    yield engine, db_session
    db_session.close()
    connection.close()

class SQLAuthenticator(Authenticator):
    def _verify_password_hash(self, hash_, password):
        try:
            input_password_hash = hashlib.md5(password.encode())
            if input_password_hash==hash_:
                return True
        except ValueError:
            return False

    @gen.coroutine
    def authenticate(self, handler, data):

        with db_session() as db:
            query = db[0].execute('SELECT * FROM users where username=?', data['username'])
            if query and self._verify_password_hash(query.password,
                                                        data['password']):
                return data['username']