from django_digest import HttpDigestAuthenticator
from django.conf import settings as django_settings
from django_digest.utils import get_setting

class HttpDigestMiddleware(object):
    def __init__(self, require_authentication=None, authenticator=None,
                 settings=django_settings):
        if require_authentication == None:
            require_authentication = get_setting(settings, 'DIGEST_REQUIRE_AUTHENTICATION',
                                                 False)
        self._authenticator = authenticator or HttpDigestAuthenticator(settings=settings)
        self._require_authentication = require_authentication

    def process_request(self, request):
        if (not self._authenticator.authenticate(request) and 
            (self._require_authentication or
             self._authenticator.contains_digest_credentials(request))):
            return self._authenticator.build_challenge_response()
        else:
            return None
        
    def process_response(self, request, response):
        if response.status_code in [401, 403]:
            return self._authenticator.build_challenge_response()
        return response
