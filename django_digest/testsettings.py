DATABASE_ENGINE = 'sqlite3'
DATABASE_NAME = ':memory:'

SECRET_KEY='the_secret_key'

INSTALLED_APPS = (
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django_digest'
    )

TEST_SETTING = False
TEST_BACKEND_SETTING = 'django_digest.tests.DummyBackendClass'
