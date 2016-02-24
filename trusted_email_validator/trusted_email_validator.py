import re
import os
import socket
import json
from dns import resolver, exception
import datetime
from collections import namedtuple
from time import mktime


class TrustedEmailValidator:
    trust_cut_off = 50
    VERSION = 1
    JSON_INDENT = 4
    SIMPLE_EMAIL_REGEX = ".*?(['_a-z0-9-\.]+@['a-z0-9-\.]+\.['a-z0-9]{2,6})"
    EMAIL_REGEX = r"^[_a-z0-9-']+(\.['_a-z0-9-]+)*@[a-z0-9-]+(\.[a-z0-9-]+)*(\.[a-z]{2,6})$"
    DIRECTORY = os.path.dirname(__file__)
    DATA_FILE_FREE_PROVIDERS = os.path.join(DIRECTORY, './data/email_providers_free.txt')
    DATA_FILE_TWO_FACTOR = os.path.join(DIRECTORY, './data/email_providers_two_factor.txt')
    DATA_FILE_COMMON_USERNAMES = os.path.join(DIRECTORY, './data/username_common_groups.txt')
    FREE_PROVIDERS_MEMORY = list()
    TWO_FACTOR_PROVIDERS_MEMORY = list()
    COMMON_USERNAMES_MEMORY = list()

    # TrustRule = namedtuple('TrustRule', 'regex reason data')

    meta_fields = 'email hostname username checked version'.split()
    mx_fields = 'has_mx mx_record mx_amount bad_lookup lookup_exception'.split()
    is_fields = 'is_valid is_email is_free is_common'.split()
    trust_fields = 'is_trusted trust_rating'.split()

    MetaData = namedtuple('MetaData', meta_fields)
    MxData = namedtuple('MxData', mx_fields)
    IsData = namedtuple('IsData', is_fields)
    TrustData = namedtuple('TrustData', trust_fields)

    AllData = namedtuple('AllData', meta_fields + mx_fields + is_fields + trust_fields)

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
        self.trust_rating = 0
        self.trust_rules_matched = list()
        self.trust_rules = list()
        self.data_mx = None
        self.data_is = None
        self.data_meta = None
        self.data_trust = None

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
        for hostname in TrustedEmailValidator.FREE_PROVIDERS_MEMORY:
            if self.hostname == hostname:
                return True

    def is_username_in_common_usernames(self):
        for username in TrustedEmailValidator.COMMON_USERNAMES_MEMORY:
            if self.username == username:
                return True

    @staticmethod
    def lazy_read_data_files():
        if not TrustedEmailValidator.FREE_PROVIDERS_MEMORY:
            TrustedEmailValidator.FREE_PROVIDERS_MEMORY = \
                [host.rstrip() for host in open(TrustedEmailValidator.DATA_FILE_FREE_PROVIDERS) if not host.startswith('#')]

        if not TrustedEmailValidator.COMMON_USERNAMES_MEMORY:
            TrustedEmailValidator.COMMON_USERNAMES_MEMORY = \
                [username.rstrip() for username in open(TrustedEmailValidator.DATA_FILE_COMMON_USERNAMES) if not username.startswith('#')]

        if not TrustedEmailValidator.TWO_FACTOR_PROVIDERS_MEMORY:
            TrustedEmailValidator.TWO_FACTOR_PROVIDERS_MEMORY = \
                [host.rstrip() for host in open(TrustedEmailValidator.DATA_FILE_TWO_FACTOR) if not host.startswith('#')]

    def init_trust_rules(self):
        self.trust_rules.append((r'^1$', 'only 1 mail server reported', self.data_mx.mx_amount))
        self.trust_rules.append((r'.*?[0-9].*?', 'numbers in username', self.username))
        self.trust_rules.append((r'.*?[A-Z][a-z].*?', 'mixed case in username', self.username))
        self.trust_rules.append((r'^(1|2)$', 'username is really small', len(self.username)))
        self.trust_rules.append((r".*?[A-Z-0-9\'_].*?", 'only upper case in username', self.username))
        self.trust_rules.append((r"^1$", 'email is from a free provider', self.data_is.is_free))

    def run_trust_rules(self):
        self.init_trust_rules()

        for rule in self.trust_rules:
            regex, reason, data = rule
            if re.match(regex, str(data)):
                self.trust_rules_matched.append(reason)

    def calc_trust_rating(self):
        rule_weight = 100 / len(self.trust_rules)
        return 100 - int(len(self.trust_rules_matched) * rule_weight)

    def execute(self):
        if self.data:
            return self.data

        TrustedEmailValidator.lazy_read_data_files()
        keep_processing = True

        self.data_meta = TrustedEmailValidator.MetaData(
            self.email, self.hostname, self.username, datetime.datetime.utcnow(), TrustedEmailValidator.VERSION
        )

        # not sure these are needed
        mx_amount = 0
        is_valid = False
        is_email = False
        is_free = False
        mx_record = (None, None)
        has_mx = False
        is_trusted = False
        is_common = False

        if re.match(TrustedEmailValidator.EMAIL_REGEX, self.email, re.IGNORECASE):
            is_email = True
        else:
            keep_processing = False

        bad_mx_lookup = None
        lookup_mx_exception = None

        if keep_processing:
            is_free = self.is_hostname_in_free()
            is_common = self.is_username_in_common_usernames()

            try:
                mx_records = resolver.query(self.hostname, 'MX', tcp=True)
                mx_amount = len(mx_records)

                for i, record in enumerate(mx_records):
                    if i == 0:
                        has_mx = True
                        is_valid = True
                        mx_record = (str(record.exchange), int(record.preference))
                    self.mx_records.append((str(record.exchange), int(record.preference)))

            except (socket.error, exception.Timeout, resolver.NXDOMAIN, resolver.NoNameservers, resolver.NoAnswer) as e:
                bad_mx_lookup = True
                lookup_mx_exception = str(e)
                keep_processing = False

        self.data_mx = TrustedEmailValidator.MxData(
            has_mx, mx_record, mx_amount, bad_mx_lookup, lookup_mx_exception
        )

        self.data_is = TrustedEmailValidator.IsData(
            is_valid, is_email, is_free, is_common,
        )

        if keep_processing:
            self.run_trust_rules()
            self.trust_rating = self.calc_trust_rating()
            if self.trust_rating > self.trust_cut_off:
                is_trusted = True

        self.data_trust = TrustedEmailValidator.TrustData(
            is_trusted,
            self.trust_rating
        )

        # _make() for a namedtuple is not protected
        self.data = TrustedEmailValidator.AllData._make(
            list(self.data_meta + self.data_mx + self.data_is + self.data_trust))

        return self.data

    def re_execute(self):
        self.data = None
        self.execute()
        return self

    def as_dict(self):
        self.execute()
        # _asdict() not protected, just named badly
        d = self.data._asdict()
        d.update(self.mx_records)
        return d

    def as_json(self):
        self.execute()
        d = self.data._asdict()
        d.update(self.mx_records)
        return json.dumps(d,
                          cls=TrustedEmailValidator.JSONEncoder,
                          # default=json_util.default,
                          indent=TrustedEmailValidator.JSON_INDENT)

if __name__ == "__main__":
    e = TrustedEmailValidator('Bill_990@gmail.com')
    print(e.as_json())
