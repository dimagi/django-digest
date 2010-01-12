from datetime import datetime

from django.contrib.auth.models import User
from django.db import IntegrityError

from django_digest.models import UserNonce, PartialDigest
from django_digest.utils import get_setting

class AccountStorage(object):
    def get_partial_digest(self, username):
        try:
            return PartialDigest.objects.get(user__username=username).partial_digest
        except PartialDigest.DoesNotExist:
            return None

    def get_user(self, username):
        try:
            return User.objects.get(username=username)
        except User.DoesNotExist:
            return None

class NonceStorage(object):
    def _expire_nonces_for_user(self, user):
        try:
            delete_older_than = UserNonce.objects.filter(user=user).order_by(
                '-last_used_at')[31].last_used_at
        except IndexError:
            # There 30 or less nonces stored
            return

        UserNonce.objects.filter(user=user, last_used_at__lte=delete_older_than).delete()


    def update_existing_nonce(self, user, nonce, nonce_count):
        nonce_query_set = UserNonce.objects.filter(user=user,
                                                   nonce=nonce)
        if not nonce_count == None:
            nonce_query_set = nonce_query_set.filter(count__lt=nonce_count)
        
        # if no rows are updated, either the nonce isn't in the DB, it's for a different
        # user, or the count is bad
        return nonce_query_set.update(last_used_at=datetime.now(), count=nonce_count)

    def store_nonce(self, user, nonce, nonce_count):
        self._expire_nonces_for_user(user)

        try:
            UserNonce.objects.create(user=user, nonce=nonce, count=nonce_count,
                                     last_used_at=datetime.now())
        except IntegrityError:
            return False
        
        return True
