import re
import os
from jupyterhub.auth import Authenticator
from tornado import gen
import hashlib
from contextlib import contextmanager
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from dotenv import load_dotenv
from traitlets import Unicode


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
    # borrowed from: https://github.com/jupyterhub/ldapauthenticator
    valid_username_regex = Unicode(
        r"^[a-z][.a-z0-9_-]*$",
        config=True,
        help="""
        Regex for validating usernames - those that do not match this regex will be rejected.
        This is primarily used as a measure against LDAP injection, which has fatal security
        considerations. The default works for most LDAP installations, but some users might need
        to modify it to fit their custom installs. If you are modifying it, be sure to understand
        the implications of allowing additional characters in usernames and what that means for
        LDAP injection issues. See https://www.owasp.org/index.php/LDAP_injection for an overview
        of LDAP injection.
        """,
    )

    def _verify_password_hash(self, hash_, password):
        try:
            input_password_hash = hashlib.md5(password.encode('utf-8')).hexdigest()
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
            if not re.match(self.valid_username_regex, data['username']):
                return None

            # No empty passwords!
            if data['password'] is None or data['password'].strip() == "":
                return None

            raw_query = "SELECT password FROM users WHERE username=%s"
            query = db[0].execute(raw_query, data['username'])
            if query and self._verify_password_hash(query.first()[0], data['password']):
            # simple check with no hash
            # if query and (query.first()[0]==data['password']):
                return data['username']