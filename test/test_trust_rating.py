import unittest
from trusted_email_validator.trusted_email_validator import TrustedEmailValidator


class TrustRatingTests(unittest.TestCase):
    """
    Tests to check that the trust rating system works
    """
    def test_should_return_not_trusted_when_bad_email(self):
        validator = TrustedEmailValidator('Bill_990@gmail.com')
        data = validator.execute()
        print(validator.trust_issues)
        self.assertFalse(data.is_trusted)

    def test_should_return_trusted_when_email_is_good(self):
        validator = TrustedEmailValidator('ShaneDevane@microsoft.com')
        data = validator.execute()
        print(validator.trust_issues)
        print(validator.trust_rating)
        self.assertTrue(data.is_trusted)
