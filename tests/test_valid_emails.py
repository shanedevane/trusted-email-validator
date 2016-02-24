import unittest
from trusted_email_validator.trusted_email_validator import TrustedEmailValidator


class ValidEmailTests(unittest.TestCase):
    """
    Tests to showcase valid emails
    """
    valid_emails = [
        "shane.devane@on.thespot.photos",
        "shaneo'donnelly@gmailbad.com",
        "shane@thisthing.museum",
        "shane@nws.li"
    ]

    def test_should_valid_when_valid_emails_are_used(self):
        for email in ValidEmailTests.valid_emails:
            self.assertTrue(TrustedEmailValidator.is_valid(email, True))

    def test_should_return_valid_when_mx_checking_is_off(self):
        validator = TrustedEmailValidator('shane@exampledomainwithnomx.com')
        self.assertFalse(validator.execute().is_valid)
        validator.skip_mx_lookup = True
        self.assertTrue(validator.re_execute().is_valid)
