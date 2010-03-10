import md5

from django.conf import settings
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.models import User
from django.db import models
from django.db.models.signals import post_save

from python_digest import calculate_partial_digest

from django_digest.utils import get_setting, DEFAULT_REALM

REALM = get_setting(settings, 'DIGEST_REALM', DEFAULT_REALM)

class UserNonce(models.Model):
    user = models.ForeignKey(User)
    nonce = models.CharField(max_length=100, unique=True, db_index=True)
    count = models.IntegerField(null=True)
    last_used_at = models.DateTimeField(null=False)
    class Meta:
        ordering = ('last_used_at',)

class PartialDigest(models.Model):
    user = models.ForeignKey(User)
    partial_digest = models.CharField(max_length=100)
    
_postponed_partial_digests = {}

def _store_partial_digest(user):
    PartialDigest.objects.filter(user=user).delete()
    PartialDigest.objects.create(user=user,
                                 partial_digest=_postponed_partial_digests[user.password])

_old_set_password = User.set_password

def _new_set_password(user, password):
    _old_set_password(user, password)
    
    partial_digest = calculate_partial_digest(user.username, REALM, password)
    _postponed_partial_digests[user.password] = partial_digest
    
User.set_password = _new_set_password

_old_authenticate = ModelBackend.authenticate

def _new_authenticate(backend, username=None, password=None):
    user = _old_authenticate(backend, username, password)
    if user:
        partial_digest = calculate_partial_digest(user.username, REALM, password)
        PartialDigest.objects.filter(user=user).delete()
        PartialDigest.objects.create(user=user, partial_digest=partial_digest)
    return user

ModelBackend.authenticate = _new_authenticate

def _persist_partial_digest(sender, instance=None, **kwargs):
    if instance is None:
        return
    if instance.password in _postponed_partial_digests:
        _store_partial_digest(instance)
        del _postponed_partial_digests[instance.password]

post_save.connect(_persist_partial_digest, sender=User)
