import unittest
from trusted_email_validator.trusted_email_validator import TrustedEmailValidator


class BasicClientIntegrationTests(unittest.TestCase):
    """
    This tests class is for coverage of the methods that clients
    can call to use TrustedEmailValidator
    """

    def test_should_work_when_is_valid_is_called(self):
        self.assertTrue(TrustedEmailValidator.is_valid("email@gmail.com"))

    def test_should_work_when_is_free_is_called(self):
        self.assertTrue(TrustedEmailValidator.is_free("email@gmail.com"))

    def test_should_work_when_re_executed(self):
        validator = TrustedEmailValidator('joesoap@gmail.com')
        first_created_time = validator.as_dict()["checked"]
        second_created_time = validator.as_dict()["checked"]

        validator = validator.re_execute()

        third_created_time = validator.as_dict()["checked"]

        self.assertEqual(first_created_time, second_created_time)
        self.assertNotEqual(second_created_time, third_created_time)

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

    def test_should_return_mx_records_when_looked_up(self):
        pass

    def test_should_not_do_mx_when_email_is_common_domain_and_mx_not_wanted(self):
        pass


