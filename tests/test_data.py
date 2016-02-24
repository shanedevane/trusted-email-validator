import unittest
from trusted_email_validator.trusted_email_validator import TrustedEmailValidator


class DataTests(unittest.TestCase):
    """
    Tests for the important data points
    Ideally, this should be bad practice to refer directly to the data
    and key attributes should be used instead
    """
    def test_should_return_valid_mx_in_data(self):
        data = TrustedEmailValidator('bill@gmail.com').as_dict()
        self.assertEqual(data["is_free"], True)

    def test_should_return_is_common_when_username_is_common(self):
        data = TrustedEmailValidator('contact@gmail.com').as_dict()
        self.assertEqual(data["is_common"], True)
