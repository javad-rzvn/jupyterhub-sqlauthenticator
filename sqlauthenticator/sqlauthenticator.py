from jupyterhub.auth import Authenticator
from tornado import gen
import hashlib
import os
from contextlib import contextmanager
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from dotenv import load_dotenv


dotenv_path = "/etc/jupyterhub/.env"
load_dotenv(dotenv_path)

@contextmanager
def db_session(db_user, db_pass, db_host, db_port, db_name):
    """ 
        Creates a context with an open SQLAlchemy session.
    """
    SQLALCHEMY_DATABASE_URL = "mysql+mysqlconnector://%s:%s@%s:%s/%s" % (
        db_user,
        db_pass,
        db_host,
        int(db_port),
        db_name,
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
        db_user=os.getenv('MYSQL_USER')
        db_pass=os.getenv('MYSQL_PASS')
        db_host=os.getenv('MYSQL_HOST')
        db_port=os.getenv('MYSQL_PORT')
        db_name=os.getenv('MYSQL_DB')
        with db_session(db_user, db_pass, db_host, db_port, db_name) as db:
            raw_query = "SELECT password FROM users WHERE username=%s"
            query = db[0].execute(raw_query, data['username'])
            if query and self._verify_password_hash(query.first()[0],
                                                        data['password']):
                return data['username']