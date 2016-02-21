import re
import os
import socket
import json
from dns import resolver, exception
import datetime
from collections import namedtuple
from bson import json_util
from time import mktime


class TrustedEmailValidator:
    SIMPLE_EMAIL_REGEX = ".*?(['_a-z0-9-\.]+@['a-z0-9-\.]+\.['a-z0-9]{2,6})"
    EMAIL_REGEX = r"^[_a-z0-9-']+(\.['_a-z0-9-]+)*@[a-z0-9-]+(\.[a-z0-9-]+)*(\.[a-z]{2,6})$"
    DIRECTORY = os.path.dirname(__file__)
    DATA_FILE_FREE_PROVIDERS = os.path.join(DIRECTORY, './data/email_providers_free.txt')
    DATA_FILE_TWO_FACTOR = os.path.join(DIRECTORY, './data/email_providers_two_factor.txt')
    SCRIPT_VERSION = 1
    JSON_INDENT = 4
    FREE_PROVIDERS_MEMORY = list()
    TWO_FACTOR_PROVIDERS_MEMORY = list()
    Data = namedtuple('Data', 'email hostname username checked version is_valid is_email is_free is_trusted '
                                      'has_mx mx_record mx_amount bad_mx_lookup lookup_mx_exception ')

    class JSONEncoder(json.JSONEncoder):
        def default(self, o):
            if isinstance(o, datetime.datetime):
                return int(mktime(o.timetuple()))

            return json.JSONEncoder(self, o)

    def __init__(self, email):
        self.email = self.clean_email(email)
        self.hostname = self.get_hostname(self.email)
        self.username = self.get_username(self.email)
        self.mx_records = list()
        self.data = None

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

    def execute(self):
        if self.data:
            return self.data

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
                        mx_record = (str(record.exchange), int(record.preference))


                    self.mx_records.append((str(record.exchange), int(record.preference)))

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
            datetime.datetime.utcnow(),
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

    def re_execute(self):
        self.data = None
        self.execute()
        return self

    def as_dict(self):
        self.execute()
        d = self.data._asdict()      # _asdict() not protected, just named badly
        d.update(self.mx_records)
        return d

    def as_json(self):
        self.execute()
        d = self.data._asdict()
        d.update(self.mx_records)
        return json.dumps(d,
                          cls=TrustedEmailValidator.JSONEncoder,
                          default=json_util.default,
                          indent=TrustedEmailValidator.JSON_INDENT)

if __name__ == "__main__":
    e = TrustedEmailValidator('bill@microsoft.com')
    print(e.as_json())
