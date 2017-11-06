from __future__ import absolute_import
from collections import OrderedDict


class WWWAuthenticateError(Exception):
    pass


class BaseAuth(object):
    def __init__(self, username, password):
        self.username = username
        self.password = password

    def _authenticate_headers(self, response):
        return OrderedDict([(value.split(' ', 1)[0], value)
                            for header, value in response.items()
                            if header == 'WWW-Authenticate'])

    def _update_headers(self, request, response):
        auth = self.authorization(request, response)
        return auth and {'HTTP_AUTHORIZATION': auth} or {}

    def __call__(self, request, response=None):
        return self._update_headers(request, response)
