import unittest
from trusted_email_validator.trusted_email_validator import TrustedEmailValidator


class TrustRatingTests(unittest.TestCase):
    """
    Tests to check that the trust rating system works
    """
    def test_should_return_trusted_when_bad_email(self):
        is_trusted = TrustedEmailValidator.is_trusted('Bill_990@gmail.com')
        self.assertFalse(is_trusted)

    def test_should_return_trusted_when_email_is_good(self):
        is_trusted = TrustedEmailValidator.is_trusted('ShaneDevane@microsoft.com')
        self.assertFalse(is_trusted)
