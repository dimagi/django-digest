 #!/usr/bin/env python
from __future__ import absolute_import
from __future__ import unicode_literals
from setuptools import setup

setup(
    name='django-digest',
    version='1.14',
    description=('An implementation of HTTP Digest Authentication for Django.'),
    long_description=(
"""
django-digest supplies a middleware (HttpDigestMiddleware) that may installed to protect access
to all URLs, a decorator (@httpdigest) that may be applied to selected view functions, and a
simple class (HttpDigestAuthenticator) that can be used to implement custom authentication
scenarios.

django-digest also supplies a subclass of django.test.Client that is able to perform Digest and
Basic authentication.
"""
    ),
    author='Akoha Inc.',
    author_email='adminmail@akoha.com',
    url='http://bitbucket.org/akoha/django-digest/',
    packages=['django_digest',
              'django_digest.backend',
              'django_digest.migrations',
              'django_digest.test',
              'django_digest.test.methods'],
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Web Environment',
        'Framework :: Django',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Software Development :: Libraries :: Python Modules'
     ],
    zip_safe=False,
)
