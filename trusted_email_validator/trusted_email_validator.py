import re
import os
import socket
from dns import resolver, exception
from datetime import datetime
from collections import namedtuple


class TrustedEmailValidator:
    SIMPLE_EMAIL_REGEX = ".*?(['_a-z0-9-\.]+@['a-z0-9-\.]+\.['a-z0-9]{2,6})"
    EMAIL_REGEX = r"^[_a-z0-9-']+(\.['_a-z0-9-]+)*@[a-z0-9-]+(\.[a-z0-9-]+)*(\.[a-z]{2,6})$"
    DIRECTORY = os.path.dirname(__file__)
    DATA_FILE_FREE_PROVIDERS = os.path.join(DIRECTORY, './data/email_providers_free.txt')
    DATA_FILE_TWO_FACTOR = os.path.join(DIRECTORY, './data/email_providers_two_factor.txt')
    SCRIPT_VERSION = 1
    FREE_PROVIDERS_MEMORY = list()
    TWO_FACTOR_PROVIDERS_MEMORY = list()
    Data = namedtuple('Data', 'email hostname username checked version is_valid is_email is_free is_trusted '
                                      'has_mx mx_record mx_amount bad_mx_lookup lookup_mx_exception ')

    def __init__(self, email):
        self.email = self.clean_email(email)
        self.hostname = self.get_hostname(self.email)
        self.username = self.get_username(self.email)
        self.mx_records = list()

        if not TrustedEmailValidator.FREE_PROVIDERS_MEMORY:
            TrustedEmailValidator.FREE_PROVIDERS_MEMORY = \
                [host.rstrip() for host in open(TrustedEmailValidator.DATA_FILE_FREE_PROVIDERS) if not host.startswith('#')]

        if not TrustedEmailValidator.TWO_FACTOR_PROVIDERS_MEMORY:
            TrustedEmailValidator.TWO_FACTOR_PROVIDERS_MEMORY = \
                [host.rstrip() for host in open(TrustedEmailValidator.DATA_FILE_TWO_FACTOR) if not host.startswith('#')]

    @staticmethod
    def clean_email(email):
        if not email:
            return email
        reg = re.match(TrustedEmailValidator.SIMPLE_EMAIL_REGEX, email, re.IGNORECASE)

        if reg:
            return reg.group(1).strip()
        else:
            return email

    @staticmethod
    def get_hostname(email):
        if not email:
            return email
        return email[email.rfind('@')+1:]

    @staticmethod
    def get_username(email):
        if not email:
            return email
        return email[:email.rfind('@')]

    @classmethod
    def is_valid(cls, email):
        email_valid = cls(email)
        return email_valid.execute().is_valid

    @classmethod
    def is_free(cls, email):
        email_valid = cls(email)
        return email_valid.execute().is_free

    @classmethod
    def is_trusted(cls, email):
        email_valid = cls(email)
        return email_valid.execute().is_trusted

    def is_hostname_in_free(self):
        # if self.hostname == "gmail.com":
        #     return True
        for hostname in TrustedEmailValidator.FREE_PROVIDERS_MEMORY:
            if self.hostname == hostname:
                return True

    @staticmethod
    def trust_rules(data):
        pass

    def as_dict(self):
        self.execute()
        data = self.decision._asdict()
        data.update(self.mx_records)
        return data

    # use strategy pattern to decide no dns lookup?

    def execute(self):
        is_valid = False
        is_email = False
        is_free = False
        mx_amount = 0
        mx_record = (None, None)
        has_mx = False
        bad_mx_lookup = None
        lookup_mx_exception = None
        is_trusted = False
        keep_processing = True

        if re.match(TrustedEmailValidator.EMAIL_REGEX, self.email, re.IGNORECASE):
            is_email = True
        else:
            keep_processing = False

        if keep_processing:
            is_free = self.is_hostname_in_free()

            try:
                mx_records = resolver.query(self.hostname, 'MX', tcp=True)
                mx_amount = len(mx_records)

                for i, record in enumerate(mx_records):
                    has_mx = True
                    if i == 0:
                        mx_record = (record.exchange, record.preference)
                    self.mx_records.append((record.exchange, record.preference))

                is_valid = True

            except (socket.error, exception.Timeout, resolver.NXDOMAIN, resolver.NoNameservers, resolver.NoAnswer) as e:
                bad_mx_lookup = True
                lookup_mx_exception = str(e)
                keep_processing = False

        if keep_processing:
            is_trusted = False

        self.data = TrustedEmailValidator.Data(
            self.email,
            self.hostname,
            self.username,
            datetime.utcnow(),
            TrustedEmailValidator.SCRIPT_VERSION,
            is_valid,
            is_email,
            is_free,
            is_trusted,
            has_mx,
            mx_record,
            mx_amount,
            bad_mx_lookup,
            lookup_mx_exception
        )

        return self.data

if __name__ == "__main__":
    TrustedEmailValidator.is_valid('bill@microsoft.com')
