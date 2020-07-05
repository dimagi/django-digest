from __future__ import absolute_import
from __future__ import unicode_literals
import logging

_l = logging.getLogger(__name__)
_l.setLevel(logging.DEBUG)

from datetime import datetime

from django.db import IntegrityError, connection, transaction

from django_digest.models import PartialDigest

class AccountStorage(object):
    GET_PARTIAL_DIGEST_QUERY = """
    SELECT django_digest_partialdigest.login, django_digest_partialdigest.partial_digest
      FROM django_digest_partialdigest
      INNER JOIN auth_user ON auth_user.id = django_digest_partialdigest.user_id
      WHERE django_digest_partialdigest.login = %s
        AND django_digest_partialdigest.confirmed
        AND auth_user.is_active
    """

    def get_partial_digest(self, username):
        cursor = connection.cursor()
        cursor.execute(self.GET_PARTIAL_DIGEST_QUERY, [username])
        # In MySQL, string comparison is case-insensitive by default.
        # Therefore a second round of filtering is required.
        row = [(row[1]) for row in cursor.fetchall() if row[0] == username]
        if not row:
            return None
        return row[0]

    def get_user(self, username):
        # In MySQL, string comparison is case-insensitive by default.
        # Therefore a second round of filtering is required.
        pds = [pd
               for pd in PartialDigest.objects.filter(login=username,
                                                      user__is_active=True)
               if pd.login == username]
        if len(pds) == 0:
            return None
        if len(pds) > 1:
            _l.warn("Multiple partial digests found for the login %r" % username)
            return None
        return pds[0].user


class NonceStorage(object):
    DELETE_OLDER_THAN_QUERY = """
    SELECT django_digest_usernonce.last_used_at FROM django_digest_usernonce
      WHERE django_digest_usernonce.user_id = %s
      ORDER BY django_digest_usernonce.last_used_at DESC LIMIT 1 OFFSET 31
    """

    DELETE_EXPIRED_NONCES_QUERY = """
    DELETE FROM django_digest_usernonce
      WHERE django_digest_usernonce.last_used_at < %s
    """

    UPDATE_EXISTING_NONCE_WITH_COUNT_QUERY = """
    UPDATE django_digest_usernonce SET count = %s, last_used_at = %s
      WHERE django_digest_usernonce.nonce = %s
        AND django_digest_usernonce.user_id = %s
        AND django_digest_usernonce.count < %s
    """

    UPDATE_EXISTING_NONCE_WITHOUT_COUNT_QUERY = """
    UPDATE django_digest_usernonce SET count = NULL, last_used_at = %s
      WHERE django_digest_usernonce.nonce = %s
        AND django_digest_usernonce.user_id = %s
    """

    INSERT_NONCE_QUERY = """
    INSERT INTO django_digest_usernonce (user_id, nonce, count, last_used_at)
      VALUES (%s, %s, %s, %s)
    """

    def _expire_nonces_for_user(self, user):
        cursor = connection.cursor()
        cursor.execute(self.DELETE_OLDER_THAN_QUERY, [user.pk])
        row = cursor.fetchone()
        if not row:
            return
        delete_older_than = row[0]
        cursor.execute(self.DELETE_EXPIRED_NONCES_QUERY, [delete_older_than])

    def update_existing_nonce(self, user, nonce, nonce_count):
        cursor = connection.cursor()
        if nonce_count == None:
            cursor.execute(
                self.UPDATE_EXISTING_NONCE_WITHOUT_COUNT_QUERY,
                [datetime.utcnow(), nonce, user.pk]
            )
        else:
            cursor.execute(
                self.UPDATE_EXISTING_NONCE_WITH_COUNT_QUERY,
                [nonce_count, datetime.utcnow(), nonce, user.pk, nonce_count]
            )
        # if no rows are updated, either the nonce isn't in the DB,
        # it's for a different user, or the count is bad
        return cursor.rowcount == 1

    def store_nonce(self, user, nonce, nonce_count):
        self._expire_nonces_for_user(user)
        cursor = connection.cursor()
        try:
            cursor.execute(
                self.INSERT_NONCE_QUERY,
                [user.pk, nonce, nonce_count, datetime.utcnow()]
            )
            return True
        except IntegrityError:
            return False
