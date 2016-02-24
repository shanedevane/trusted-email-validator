import unittest
from trusted_email_validator.trusted_email_validator import TrustedEmailValidator


class TestReadingProviderDataFiles(unittest.TestCase):

    def test_should_not_read_data_files_when_called_multiple_times(self):
        validator = TrustedEmailValidator('shane@gmail.com')
        self.assertEqual(validator._FREE_PROVIDERS_MEMORY, list())
        validator.execute()
        self.assertNotEqual(validator._FREE_PROVIDERS_MEMORY, None)
        validator.re_execute()
        self.assertNotEqual(validator._FREE_PROVIDERS_MEMORY, None)
        new_validator = TrustedEmailValidator('devane@gmail.com')
        new_validator.execute()
        self.assertNotEqual(validator._FREE_PROVIDERS_MEMORY, None)
