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
    json_indent = 4
    simple_email_regex = r".*?(['_a-z0-9-\.]+@['a-z0-9-\.]+\.['a-z0-9]{2,6})"
    email_regex = r"^[_a-z0-9-']+(\.['_a-z0-9-]+)*@[a-z0-9-]+(\.[a-z0-9-]+)*(\.[a-z]{2,6})$"

    _FREE_PROVIDERS_MEMORY = list()
    _COMMON_USERNAMES_MEMORY = list()
    _version = 1
    _directory = os.path.dirname(__file__)
    _data_file_free_providers = os.path.join(_directory, './data/email_providers_free.txt')
    _data_file_common_usernames = os.path.join(_directory, './data/username_common_groups.txt')
    _meta_fields = 'email hostname username checked version'.split()
    _mx_fields = 'has_mx mx_record mx_amount bad_lookup lookup_exception'.split()
    _is_fields = 'is_valid is_email is_free is_common'.split()
    _trust_fields = 'is_trusted trust_rating'.split()
    _MetaData = namedtuple('MetaData', _meta_fields)
    _MxData = namedtuple('MxData', _mx_fields)
    _IsData = namedtuple('IsData', _is_fields)
    _TrustData = namedtuple('TrustData', _trust_fields)
    _AllData = namedtuple('AllData', _meta_fields + _mx_fields + _is_fields + _trust_fields)

    def __init__(self, email):
        self.email = email
        self.email = self._clean_email()
        self.hostname = self._get_hostname()
        self.username = self._get_username()
        self.mx_records = list()
        self.data = None
        self.trust_rating = 0
        self.trust_issues = list()
        self.trust_rules = list()
        self.data_mx = None
        self.data_is = None
        self.data_meta = None
        self.data_trust = None

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

    class JSONEncoder(json.JSONEncoder):
        def default(self, o):
            if isinstance(o, datetime.datetime):
                return int(mktime(o.timetuple()))
            return json.JSONEncoder(self, o)

    def _clean_email(self):
        if self.email:
            reg = re.match(self.simple_email_regex, self.email, re.IGNORECASE)
            if reg:
                return reg.group(1).strip()

    def _get_hostname(self):
        if self.email:
            return self.email[self.email.rfind('@')+1:]

    def _get_username(self):
        if self.email:
            return self.email[:self.email.rfind('@')]

    def _is_hostname_in_free(self):
        for hostname in TrustedEmailValidator._FREE_PROVIDERS_MEMORY:
            if self.hostname == hostname:
                return True

    def _is_username_in_common_usernames(self):
        for username in TrustedEmailValidator._COMMON_USERNAMES_MEMORY:
            if self.username == username:
                return True

    @classmethod
    def _lazy_read_data_files(cls):
        if not cls._FREE_PROVIDERS_MEMORY:
            cls._FREE_PROVIDERS_MEMORY = \
                [host.rstrip()
                 for host in open(cls._data_file_free_providers)
                 if not host.startswith('#')]

        if not cls._COMMON_USERNAMES_MEMORY:
            cls._COMMON_USERNAMES_MEMORY = \
                [username.rstrip()
                 for username in open(cls._data_file_common_usernames)
                 if not username.startswith('#')]

    def _init_trust_rules(self):
        self.trust_rules.append((r'^1$', 'only 1 mail server reported', self.data_mx.mx_amount))
        self.trust_rules.append((r'.*?[0-9]+.*?', 'numbers in username', self.username))
        self.trust_rules.append((r'.*?[A-Z]+[a-z]+.*?', 'mixed case in username', self.username))
        self.trust_rules.append((r'^(1|2)$', 'username is really small', len(self.username)))
        self.trust_rules.append((r"^[A-Z-0-9\'_]+$", 'only upper case in username', self.username))
        self.trust_rules.append((r"^True$", 'email is from a free provider', self.data_is.is_free))

    def _run_trust_rules(self):
        self._init_trust_rules()

        for rule in self.trust_rules:
            regex, reason, data = rule
            if re.match(regex, str(data)):
                self.trust_issues.append(reason)

    def _calc_trust_rating(self):
        rule_weight = 100 / len(self.trust_rules)
        return 100 - int(len(self.trust_issues) * rule_weight)

    def execute(self):
        if self.data:
            return self.data

        self._lazy_read_data_files()
        keep_processing = True

        self.data_meta = TrustedEmailValidator._MetaData(
            self.email, self.hostname, self.username, datetime.datetime.utcnow(), TrustedEmailValidator._version
        )

        is_email = False
        if self.email:
            if re.match(self.email_regex, self.email, re.IGNORECASE):
                is_email = True
            else:
                keep_processing = False
        else:
            keep_processing = False

        bad_mx_lookup = None
        lookup_mx_exception = None
        mx_record = (None, None)
        mx_amount = 0
        has_mx = False
        is_valid = False
        is_free = False
        is_common = False

        if keep_processing:
            is_free = self._is_hostname_in_free()
            is_common = self._is_username_in_common_usernames()

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

        self.data_mx = TrustedEmailValidator._MxData(
            has_mx, mx_record, mx_amount, bad_mx_lookup, lookup_mx_exception
        )

        self.data_is = TrustedEmailValidator._IsData(
            is_valid, is_email, is_free, is_common,
        )

        is_trusted = False
        if keep_processing:
            self._run_trust_rules()
            self.trust_rating = self._calc_trust_rating()

            if self.trust_rating > self.trust_cut_off:
                is_trusted = True

        self.data_trust = TrustedEmailValidator._TrustData(
            is_trusted,
            self.trust_rating
        )

        # _make() for a namedtuple is not protected
        self.data = TrustedEmailValidator._AllData._make(
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
                          indent=self.json_indent)

if __name__ == "__main__":
    e = TrustedEmailValidator('Bill_990@gmail.com')
    e.JSON_INDENT = 0
    print(e.as_json())
