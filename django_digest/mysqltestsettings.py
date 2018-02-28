from __future__ import absolute_import
from __future__ import unicode_literals
from django_digest.testsettings import *
INSTALLED_APPS += ('south',)

DATABASE_ENGINE = 'mysql' 
DATABASE_STORAGE_ENGINE = 'InnoDB'
DATABASE_HOST = 'localhost'
DATABASE_PORT = 3306
DATABASE_NAME = 'django_digest'
DATABASE_USER = 'root'
DATABASE_PASSWORD = ''

try:
    from django_digest.developer_settings import *
except ImportError:
    pass
