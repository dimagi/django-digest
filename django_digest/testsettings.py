DATABASE_ENGINE = 'sqlite3'
DATABASE_NAME = ':memory:'
ROOT_URLCONF = ['django_digest.urls']

MIDDLEWARE_CLASSES = (
    'django.middleware.common.CommonMiddleware',
    'django_digest.middleware.HttpDigestMiddleware',
)

SECRET_KEY='the_secret_key'
DIGEST_REALM='TEST_REALM'

INSTALLED_APPS = (
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django_digest'
    )

TEST_SETTING = False
TEST_BACKEND_SETTING = 'django_digest.tests.DummyBackendClass'
