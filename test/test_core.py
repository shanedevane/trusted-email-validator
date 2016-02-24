import unittest
from trusted_email_validator.trusted_email_validator import TrustedEmailValidator


class BasicClientIntegrationTests(unittest.TestCase):
    """
    This test class is for coverage of the methods that clients
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




