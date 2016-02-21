import unittest
from trusted_email_validator.trusted_email_validator import TrustedEmailValidator


class MxRecordTests(unittest.TestCase):
    def test_should_return_valid_when_email_has_valid_mx(self):
        self.assertTrue(TrustedEmailValidator.is_valid('bill@microsoft.com'))

    def test_should_return_invalid_when_domain_not_valid(self):
        self.assertFalse(TrustedEmailValidator.is_valid('testing@dom[]ain.com'))

    def test_should_return_invalid_when_email_has_no_mx(self):
        self.assertFalse(TrustedEmailValidator.is_valid('testing@example.com'))

    def test_should_return_valid_when_email_is_weird_but_valid(self):
        self.assertTrue(TrustedEmailValidator.is_valid("tes'ting@gmail.com"))

    def test_should_return_valid_when_email_ends_in_space(self):
        self.assertTrue(TrustedEmailValidator.is_valid("testing@gmail.com "))

    def test_should_return_invalid_when_no_email_is_passed(self):
        self.assertFalse(TrustedEmailValidator.is_valid(""))

    def test_should_return_valid_when_email_is_uppercase(self):
        self.assertTrue(TrustedEmailValidator.is_valid("SHANEDEVANE@SHANEDEVANE.COM"))

    def test_should_return_valid_when_email_includes_full_name_convention(self):
        self.assertTrue(TrustedEmailValidator.is_valid("Shane Devane <thingy@gmail.com>"))

    def test_should_return_valid_when_a_sentence_is_passed_in(self):
        self.assertTrue(TrustedEmailValidator.is_valid
                        ("This is something that I want to do thingy@gmail.com."))

    def test_should_return_valid_when_email_is_worst_tld_in_the_world(self):
        self.assertTrue(TrustedEmailValidator.is_valid("shane@ima.museum"))

    def test_should_return_valid_when_mx_checking_is_off(self):
        pass

    def test_should_return_invalid_when_regex_not_match(self):
        pass

    def test_should_return_soft_valid_when_regex_not_match(self):
        pass

    def test_should_return_mx_records_when_looked_up(self):
        pass

    def test_should_fix_common_type_when_common_domain_is_wrong(self):
        pass

    def test_should_not_do_mx_when_email_is_common_domain_and_mx_not_wanted(self):
        pass



# (usernames with numbers in them!)
# weird characters at the start are weird
# ALL UPPERCASE IS ALSO WEIRD
# upper case name if it's included is weird
# if free email account, and weird numbers then no trust
# if free, and looks good, then cool
# if single word person name 'MADDONNA' then no trust

# what is a good name and email address??

# max trust firstname.lastname@companyname.com
# firstinitiallastname@companyname.com

