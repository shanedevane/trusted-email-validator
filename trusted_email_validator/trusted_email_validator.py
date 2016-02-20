import re
import smtplib
import logging
import socket
from datetime import datetime
from collections import namedtuple


class TrustedEmailValidator:
    SIMPLE_EMAIL_REGEX = r"['_a-z0-9-\.]+@['a-z0-9-\.]+\.['_a-z0-9]{2,6}"
    EMAIL_REGEX = r"^[_a-z0-9-']+(\.['_a-z0-9-]+)*@[a-z0-9-]+(\.[a-z0-9-]+)*(\.[a-z]{2,6})$"
    PERFORM_DNS_LOOKUP = True
    DATA_FILE_FREE_PROVIDERS = ''
    DATA_FILE_TWO_FACTOR = ''
    SCRIPT_VERSION = 1

    def __init__(self, email, dns_lookup=True):
        self.email = self.clean_email(email)
        self.perform_dns_lookup = dns_lookup

    @staticmethod
    def clean_email(email):
        parsed_email = re.match(TrustedEmailValidator.SIMPLE_EMAIL_REGEX, email, re.IGNORECASE)
        parsed_email = parsed_email.group(1).strip()
        return parsed_email

    @classmethod
    def is_valid(cls, email):
        email_valid = cls(email)
        return email_valid.execute().is_valid

    @classmethod
    def is_free(cls, email):
        email_valid = cls(email)
        return email_valid.execute().is_free

    @classmethod
    def is_disposable(cls, email):
        email_valid = cls(email)
        return email_valid.execute().is_disposable

    @classmethod
    def is_trusted(cls, email):
        email_valid = cls(email)
        return email_valid.execute().is_trusted

    def trust_rules(self):
        pass

    # use strategy pattern to decide no dns lookup?

    def execute(self):
        keep_progressing = True
        decision = namedtuple('Decision', [
            'email',
            'checked',
            'version',
            'is_valid',
            'is_free',
            'is_disposable',
            'is_trusted',
        ])

        print(self.email)

        decision.checked = datetime.utcnow()
        decision.version = TrustedEmailValidator.SCRIPT_VERSION

        if re.match(TrustedEmailValidator.EMAIL_REGEX, self.email, re.IGNORECASE):
            decision.is_valid = True
        else:
            decision.is_valid = False
            keep_progressing = False

        return decision
