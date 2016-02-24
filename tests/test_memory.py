import unittest
from trusted_email_validator.trusted_email_validator import TrustedEmailValidator


class TestReadingProviderDataFiles(unittest.TestCase):
    """
    When unit tests are run via pytest etc. on the first
    execute() to the very first test the data files are cached
    via lru decorator and unit tests should be idempotent
    so this required a work around via an incremental variable
    """
    def test_should_not_read_data_files_when_called_multiple_times(self):
        validator = TrustedEmailValidator('shane@gmail.com')
        validator.execute()
        self.assertEqual(validator._cache_load, 2)
        validator.re_execute()
        self.assertEqual(validator._cache_load, 2)
        new_validator = TrustedEmailValidator('devane@gmail.com')
        new_validator.execute()
        self.assertEqual(validator._cache_load, 2)
