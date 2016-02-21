import unittest
from trusted_email_validator.trusted_email_validator import TrustedEmailValidator


class DataTests(unittest.TestCase):
    def test_should_return_valid_mx_in_data(self):
        data = TrustedEmailValidator('bill@gmail.com').as_dict()
        self.assertEqual(data["is_free"], True)

