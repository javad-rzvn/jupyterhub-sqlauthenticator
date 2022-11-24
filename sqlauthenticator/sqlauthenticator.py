from jupyterhub.auth import Authenticator
from tornado import gen
# from passlib.hash import pbkdf2_sha256
import hashlib
import pymysql.cursors
import os


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
        conn = pymysql.connect(host=os.getenv('MYSQL_HOST'),
                               port=int(os.getenv('MYSQL_PORT', 0)),
                               user=os.getenv('MYSQL_USER'),
                               password=os.getenv('MYSQL_PASS'),
                               db=os.getenv('MYSQL_DB'),
                               charset='utf8mb4',
                               cursorclass=pymysql.cursors.DictCursor)

        try:
            with conn.cursor() as cursor:
                user = conn.escape(data['username'])
                sql = 'SELECT `password` FROM `users` WHERE `username` = {}'
                sql_formatted = sql.format(user)

                cursor.execute(sql_formatted)
                result = cursor.fetchone()
                if result and self._verify_password_hash(result['password'],
                                                         data['password']):
                    return data['username']

        finally:
            conn.close()
