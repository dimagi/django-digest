from __future__ import absolute_import
from __future__ import unicode_literals
from django_digest import HttpDigestAuthenticator
from django_digest.utils import get_setting

class HttpDigestMiddleware(object):
    def __init__(self, require_authentication=None, authenticator=None):
        if require_authentication == None:
            require_authentication = get_setting('DIGEST_REQUIRE_AUTHENTICATION',
                                                 False)
        self._authenticator = authenticator or HttpDigestAuthenticator()
        self._require_authentication = require_authentication

    def process_request(self, request):
        if (not self._authenticator.authenticate(request) and
            (self._require_authentication or
             self._authenticator.contains_digest_credentials(request))):
            return self._authenticator.build_challenge_response()
        else:
            return None

    def process_response(self, request, response):
        if response.status_code == 401:
            return self._authenticator.build_challenge_response()
        return response


class HttpDigestMiddleware2(object):
    """The HTTP digest authentication middleware, for Django
    since version 1.10.

    Args:
        get_response (Callable): The callable that takes the HTTP
                                 request and returns the response

    Attributes:
        get_response (Callable): The callable that takes the HTTP
                                 request and returns the response
    """
    get_response = None

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        authenticator = HttpDigestAuthenticator()
        if (not authenticator.authenticate(request) and
            (get_setting("DIGEST_REQUIRE_AUTHENTICATION", False) or
             authenticator.contains_digest_credentials(request))):
            return authenticator.build_challenge_response()
        response = self.get_response(request)
        if response.status_code == 401:
            return authenticator.build_challenge_response()
        return response
