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
