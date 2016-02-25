import os
from trusted_email_validator import __version__
from setuptools import setup

with open(os.path.join(os.path.dirname(__file__), 'README.md')) as readme:
    README = readme.read()

os.chdir(os.path.normpath(os.path.join(os.path.abspath(__file__), os.pardir)))

#be pyemailvalidator

setup(
    name='trusted_email_validator',
    version=__version__,
    packages=['trusted_email_validator'],
    author='Shane Devane',
    author_email='shanedevane@gmail.com',
    description='Email Validator with Trust Rules',
    long_description=README,
    license='GPL',
    keywords='email mx validate dns trust',
    url='https://github.com/shanedevane/trusted-email-validator',
    zip_safe=False,
    include_package_data=True,
    test_suite='tests',
)
