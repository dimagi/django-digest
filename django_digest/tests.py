from __future__ import with_statement
from django.test import TestCase

import time

from mocker import Mocker, expect

import python_digest
from python_digest.utils import parse_parts

from django.conf import settings as django_settings
from django.contrib.auth.models import User
from django.http import HttpRequest

from django_digest import HttpDigestAuthenticator
from django_digest.backend.db import AccountStorage
from django_digest.decorators import httpdigest
from django_digest.middleware import HttpDigestMiddleware
from django_digest.models import PartialDigest
from django_digest.utils import get_setting, get_backend, DEFAULT_REALM

class DummyBackendClass(object):
    pass

class OtherDummyBackendClass(object):
    pass

class DummySettings(object):
    def __init__(self):
        self.A_PRESENT_SETTING = 'hello'
        self.A_FALSE_SETTING = False
        self.A_PRESENT_BACKEND_SETTING = 'django_digest.tests.DummyBackendClass'
        self.SECRET_KEY = 'sekret'
        self.DIGEST_ENFORCE_NONCE_COUNT = True
        if hasattr(django_settings, 'DIGEST_REALM'):
            self.DIGEST_REALM = django_settings.DIGEST_REALM

class UtilsTest(TestCase):
    def test_get_setting(self):
        settings = DummySettings()
        self.assertEqual('hello', get_setting(settings, 'A_PRESENT_SETTING', 'blah'))
        self.assertEqual('blah', get_setting(settings, 'AN_ABSENT_SETTING', 'blah'))
        self.assertEqual(False, get_setting(settings, 'A_FALSE_SETTING', 'blah'))

    def test_get_backend(self):
        settings = DummySettings()
        self.assertEqual(DummyBackendClass,
                         type(get_backend(settings, 'A_PRESENT_BACKEND_SETTING',
                                          'django_digest.tests.OtherDummyBackendClass')))
        self.assertEqual(OtherDummyBackendClass,
                         type(get_backend(settings, 'AN_ABSENT_BACKEND_SETTING',
                                          'django_digest.tests.OtherDummyBackendClass')))


class DjangoDigestTests(TestCase):
    def setUp(self):
        self.mocker = Mocker()
        self.settings = DummySettings()
        
    def create_mock_request(self, username='dummy-username', realm=None,
                            method='GET', uri='/dummy/uri', nonce=None, request_digest=None,
                            algorithm=None, opaque='dummy-opaque', qop='auth', nonce_count=1,
                            client_nonce=None, password='password', request_path=None,
                            settings=None):
        if settings is None:
            settings = self.settings
        if not realm:
            realm = get_setting(settings, 'DIGEST_REALM', DEFAULT_REALM)
        if not nonce:
            nonce=python_digest.calculate_nonce(time.time(), secret=settings.SECRET_KEY)
        if not request_path:
            request_path = uri
        header = python_digest.build_authorization_request(
            username=username, realm=realm, method=method, uri=uri, nonce=nonce, opaque=opaque,
            nonce_count=nonce_count, password=password, request_digest=request_digest,
            client_nonce=client_nonce)

        request = self.create_mock_request_for_header(header)

        expect(request.method).result(method)
        expect(request.path).result(request_path)

        return request

    def create_mock_request_for_header(self, header):
        request = self.mocker.mock(HttpRequest, count=False)

        # bug in mocker: https://bugs.launchpad.net/mocker/+bug/179072
        try:
            'HTTP_AUTHORIZATION' in request.META
        except:
            pass
        self.mocker.result(not header == None)

        if header:
            expect(request.META['HTTP_AUTHORIZATION']).count(0, None).result(header)

        return request

    def test_build_challenge_response(self):
        response = HttpDigestAuthenticator(settings=self.settings).build_challenge_response()
        self.assertEqual(401, response.status_code)
        self.assertEqual('digest ', response["WWW-Authenticate"][:7].lower())
        parts = parse_parts(response["WWW-Authenticate"][7:])
        self.assertEqual(get_setting(self.settings, 'DIGEST_REALM', DEFAULT_REALM),
                         parts['realm'])

    def test_decorator_authenticated_with_parens(self):
        response = self.mocker.mock(count=False)
        expect(response.status_code).result(200)

        @httpdigest()
        def test_view(request):
            return response

        testuser = User.objects.create_user('testuser', 'user@example.com', 'pass')
        request = self.create_mock_request(username=testuser.username, password='pass',
                                           settings=django_settings)
        request.user = testuser

        with self.mocker:
            self.assertEqual(response, test_view(request))
        
    def test_decorator_authenticated_without_parens(self):
        response = self.mocker.mock(count=False)
        expect(response.status_code).result(200)

        @httpdigest
        def test_view(request):
            return response

        testuser = User.objects.create_user('testuser', 'user@example.com', 'pass')
        request = self.create_mock_request(username=testuser.username, password='pass',
                                           settings=django_settings)
        request.user = testuser

        with self.mocker:
            self.assertEqual(response, test_view(request))
        
    def test_decorator_authenticated_with_full_uri(self):
        response = self.mocker.mock(count=False)
        expect(response.status_code).result(200)
        
        @httpdigest
        def test_view(request):
            return response

        testuser = User.objects.create_user('testuser', 'user@example.com', 'pass')
        request = self.create_mock_request(username=testuser.username, password='pass',
                                           uri='http://server:8000/some/path?q=v',
                                           request_path='/some/path', settings=django_settings)
        request.user = testuser

        with self.mocker:
            self.assertEqual(response, test_view(request))
        
    def test_decorator_with_realm_mismatch(self):
        response = self.mocker.mock(count=False)

        @httpdigest
        def test_view(request):
            return response

        testuser = User.objects.create_user('testuser', 'user@example.com', 'pass')
        request = self.create_mock_request(username=testuser.username, password='pass',
                                           realm='BAD_REALM', settings=django_settings)

        with self.mocker:
            final_response = test_view(request)
            self.assertEqual(401, final_response.status_code)
            self.assertTrue('WWW-Authenticate' in final_response)
        
    def test_decorator_unauthenticated_and_custom_settings(self):
        response = self.mocker.mock(count=False)
        expect(response.status_code).result(200)

        @httpdigest(realm='MY_TEST_REALM')
        def test_view(request):
            return response

        testuser = User.objects.create_user('testuser', 'user@example.com', 'pass')
        request = self.create_mock_request_for_header(None)
        request.user = testuser

        with self.mocker:
            final_response = test_view(request)
            self.assertEqual(401, final_response.status_code)
            self.assertTrue('WWW-Authenticate' in final_response)
            self.assertTrue('MY_TEST_REALM' in final_response['WWW-Authenticate'])
        
    def test_decorator_with_pre_constructed_authenticator(self):
        response = self.mocker.mock(count=False)
        expect(response.status_code).result(200)

        @httpdigest(HttpDigestAuthenticator(realm='MY_TEST_REALM'))
        def test_view(request):
            return response

        testuser = User.objects.create_user('testuser', 'user@example.com', 'pass')
        request = self.create_mock_request_for_header(None)
        request.user = testuser

        with self.mocker:
            final_response = test_view(request)
            self.assertEqual(401, final_response.status_code)
            self.assertTrue('WWW-Authenticate' in final_response)
            self.assertTrue('MY_TEST_REALM' in final_response['WWW-Authenticate'])

    def test_disable_nonce_count_enforcement(self):
        self.settings.DIGEST_ENFORCE_NONCE_COUNT = False
        testuser = User.objects.create_user(username='testuser', 
                                            email='user@example.com',
                                            password='pass')

        nonce=python_digest.calculate_nonce(time.time(), secret=self.settings.SECRET_KEY)

        first_request = self.create_mock_request(username=testuser.username,
                                                 password='pass', nonce=nonce,
                                                 settings=self.settings)
        first_request.user = testuser
        
        # same nonce, same nonce count, will succeed
        second_request = self.create_mock_request(username=testuser.username,
                                                  password='pass', nonce=nonce,
                                                  settings=self.settings)
        second_request.user = testuser
        with self.mocker:
            authenticator = HttpDigestAuthenticator(settings=self.settings)
            self.assertTrue(authenticator.authenticate(first_request))
            self.assertTrue(authenticator.authenticate(second_request))

    def test_authenticate(self):
        testuser = User.objects.create_user('testuser', 'user@example.com', 'pass')
        otheruser = User.objects.create_user('otheruser', 'otheruser@example.com', 'pass')

        nonce=python_digest.calculate_nonce(time.time(), secret=self.settings.SECRET_KEY)

        first_request = self.create_mock_request(username=testuser.username,
                                                 password='pass', nonce=nonce)
        first_request.user = testuser

        # same nonce, same nonce count, will fail
        second_request = self.create_mock_request(username=testuser.username,
                                                  password='pass', nonce=nonce)

        # same nonce, new nonce count, it works
        third_request = self.create_mock_request(username=testuser.username,
                                                 password='pass', nonce=nonce,
                                                 nonce_count=2)
        third_request.user = testuser

        # an invalid request
        fourth_request = self.create_mock_request_for_header('Digest blah blah blah')

        # an invalid request
        fifth_request = self.create_mock_request_for_header(None)

        # an invalid nonce
        sixth_request = self.create_mock_request(
            username=testuser.username, password='pass', nonce_count=1,
            nonce=python_digest.calculate_nonce(time.time(), secret='bad secret'))

        # an invalid request digest (wrong password)
        seventh_request = self.create_mock_request(
            username=testuser.username, password='wrong', nonce=nonce, nonce_count=3)

        # attack attempts / failures don't invalidate the session or increment nonce_cont
        eighth_request = self.create_mock_request(username=testuser.username,
                                                  password='pass', nonce=nonce, nonce_count=3)
        eighth_request.user = testuser

        # mismatched URI
        ninth_request = self.create_mock_request(username=testuser.username, nonce=nonce,
                                                 password='pass', nonce_count=4,
                                                 request_path='/different/path')

        # stale nonce
        tenth_request = self.create_mock_request(
            username=testuser.username, password='pass', nonce_count=4,
            nonce=python_digest.calculate_nonce(time.time()-60000,
                                                secret=self.settings.SECRET_KEY))

        # once the nonce is used by one user, can't be reused by another
        eleventh_request = self.create_mock_request(username=otheruser.username,
                                                  password='pass', nonce=nonce, nonce_count=4)

        # if the partial digest is not in the DB, authentication fails
        twelfth_request = self.create_mock_request(username=testuser.username,
                                                   password='pass', nonce_count=3)
        
        # a request for Basic auth
        thirteenth_request = self.create_mock_request_for_header('Basic YmxhaDpibGFo')

        authenticator = HttpDigestAuthenticator(settings=self.settings)
        with self.mocker:
            self.assertTrue(HttpDigestAuthenticator.contains_digest_credentials(first_request))
            self.assertTrue(authenticator.authenticate(first_request))
            self.assertFalse(authenticator.authenticate(second_request))
            self.assertTrue(authenticator.authenticate(third_request))
            self.assertFalse(authenticator.authenticate(fourth_request))
            self.assertFalse(authenticator.authenticate(fifth_request))
            self.assertFalse(authenticator.authenticate(sixth_request))
            self.assertFalse(authenticator.authenticate(seventh_request))
            self.assertTrue(authenticator.authenticate(eighth_request))
            self.assertFalse(authenticator.authenticate(ninth_request))
            self.assertFalse(authenticator.authenticate(tenth_request))
            self.assertFalse(authenticator.authenticate(eleventh_request))

            PartialDigest.objects.all().delete()
            self.assertFalse(authenticator.authenticate(twelfth_request))
            self.assertFalse(authenticator.authenticate(thirteenth_request))

class ModelsTests(TestCase):
    def test_partial_digest_creation_on_set_password(self):
        user = User.objects.create(username='testuser', email='testuser@example.com')
        self.assertEqual(0,PartialDigest.objects.count())
        user.set_password('password')
        self.assertEqual(0,PartialDigest.objects.count())
        user.save()
        self.assertEqual(1,PartialDigest.objects.count())

    def test_partial_digest_creation_on_login(self):
        user = User.objects.create_user(username='testuser', password='password',
                                        email='testuser@example.com')
        PartialDigest.objects.get(user=user).delete()
        self.assertEqual(0,PartialDigest.objects.count())
        from django.contrib.auth import authenticate
        self.assertEqual(user, authenticate(username='testuser', password='password'))
        self.assertEqual(1,PartialDigest.objects.count())

class MiddlewareTests(TestCase):
    def setUp(self):
        self.mocker = Mocker()

    def test_valid_login(self):
        authenticator = self.mocker.mock()
        request = self.mocker.mock()
        expect(authenticator.authenticate(request)).result(True)
        with self.mocker:
            self.assertEqual(
                None, HttpDigestMiddleware(authenticator=authenticator).process_request(request))

    def test_no_login_and_not_required(self):
        authenticator = self.mocker.mock()
        request = self.mocker.mock()
        expect(authenticator.authenticate(request)).result(False)
        expect(authenticator.contains_digest_credentials(request)).result(False)
        with self.mocker:
            self.assertEqual(
                None, HttpDigestMiddleware(authenticator=authenticator).process_request(request))

    def test_no_login_and_required(self):
        authenticator = self.mocker.mock(count=False)
        request = self.mocker.mock()
        response = self.mocker.mock()
        expect(authenticator.authenticate(request)).result(False)
        expect(authenticator.contains_digest_credentials(request)).result(False)
        expect(authenticator.build_challenge_response()).result(response)
        with self.mocker:
            self.assertEqual(
                response,
                HttpDigestMiddleware(authenticator=authenticator,
                                     require_authentication=True).process_request(request))

    def test_process_response_401(self):
        authenticator = self.mocker.mock(count=False)
        request = self.mocker.mock()
        response = self.mocker.mock(count=False)
        challenge_response = self.mocker.mock()
        expect(response.status_code).result(401)
        expect(authenticator.build_challenge_response()).result(challenge_response)
        with self.mocker:
            self.assertEqual(
                challenge_response,
                HttpDigestMiddleware(authenticator=authenticator).process_response(
                    request, response))

    def test_process_response_403(self):
        authenticator = self.mocker.mock(count=False)
        request = self.mocker.mock()
        response = self.mocker.mock(count=False)
        challenge_response = self.mocker.mock()
        expect(response.status_code).result(403)
        expect(authenticator.build_challenge_response()).result(challenge_response)
        with self.mocker:
            self.assertEqual(
                challenge_response,
                HttpDigestMiddleware(authenticator=authenticator).process_response(
                    request, response))
        
    def test_process_response_200(self):
        authenticator = self.mocker.mock(count=False)
        request = self.mocker.mock()
        response = self.mocker.mock(count=False)
        expect(response.status_code).result(200)
        with self.mocker:
            self.assertEqual(
                response,
                HttpDigestMiddleware(authenticator=authenticator).process_response(
                    request, response))
        
    def test_process_response_404(self):
        authenticator = self.mocker.mock(count=False)
        request = self.mocker.mock()
        response = self.mocker.mock(count=False)
        expect(response.status_code).result(404)
        with self.mocker:
            self.assertEqual(
                response,
                HttpDigestMiddleware(authenticator=authenticator).process_response(
                    request, response))

class DbBackendTests(TestCase):
    def test_get_partial_digest(self):
        user1 = User.objects.create(username='user1', email='user1@example.com')
        user2 = User.objects.create_user(username='user2', email='user2@example.com',
                                         password='pass')
        self.assertEqual(None, AccountStorage().get_partial_digest(user1.username))
        self.assertTrue(AccountStorage().get_partial_digest(user2.username) is not None)
        self.assertEqual(None, AccountStorage().get_partial_digest('user3'))

    def test_get_user(self):
        user1 = User.objects.create(username='user1', email='user1@example.com')
        user2 = User.objects.create_user(username='user2', email='user2@example.com',
                                         password='pass')
        self.assertEqual(user1, AccountStorage().get_user(user1.username))
        self.assertEqual(user2, AccountStorage().get_user(user2.username))
        self.assertEqual(None, AccountStorage().get_user('user3'))
