from trusted_email_validator import __version__
from setuptools import setup

#be pyemailvalidator

setup(
    name='trusted_email_validator',
    version=__version__,
    packages=['trusted_email_validator' ],
    author='Shane Devane',
    author_email='shanedevane@gmail.com',
    description='Email Validator with Trust Rules',
    license='GPL',
    keywords='email mx validate dns trust',
    url='https://github.com/shanedevane/trusted-email-validator',
    zip_safe=False,
    test_suite='tests',
)
