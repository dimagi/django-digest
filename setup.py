 #!/usr/bin/env python
from setuptools import setup

setup(
    name='django-digest',
    version='1.0',
    description=('An implementation of HTTP Digest Authentication for Django.'),
    long_description=(
"""
"""
    ),
    author='Akoha Inc.',
    author_email='adminmail@akoha.com',
    url='http://bitbucket.org/akoha/django-digest/',
    packages=['django_digest',
              'django_digest.backend'],
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Web Environment',
        'Framework :: Django',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Software Development :: Libraries :: Python Modules'
     ],
    zip_safe=True,
)
