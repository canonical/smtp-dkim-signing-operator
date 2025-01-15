import os
import shutil
import sys
import tempfile
import unittest

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__)))))
from lib import utils  # NOQA: E402


class TestLibUtils(unittest.TestCase):
    def setUp(self):
        self.maxDiff = None
        self.tmpdir = tempfile.mkdtemp(prefix='charm-unittests-')
        self.addCleanup(shutil.rmtree, self.tmpdir)

    def test_logrotate_frequency(self):
        with open('tests/unit/files/logrotate_frequency', 'r') as f:
            want = f.read()
        self.assertEqual(utils.update_logrotate_conf('tests/unit/files/logrotate', frequency='daily'), want)

    def test_logrotate_non_exists(self):
        self.assertEqual(
            utils.update_logrotate_conf('tests/unit/files/logrotate_file_does_not_exist', frequency='daily'), ''
        )

    def test_logrotate_retention(self):
        with open('tests/unit/files/logrotate_retention', 'r') as f:
            want = f.read()
        self.assertEqual(utils.update_logrotate_conf('tests/unit/files/logrotate', retention=30), want)

    def test_logrotate_retention_no_dateext(self):
        with open('tests/unit/files/logrotate_retention_no_dateext', 'r') as f:
            want = f.read()
        self.assertEqual(utils.update_logrotate_conf('tests/unit/files/logrotate', retention=30, dateext=False), want)

        with open('tests/unit/files/logrotate_retention_no_dateext', 'r') as f:
            want = f.read()
        self.assertEqual(
            utils.update_logrotate_conf('tests/unit/files/logrotate_retention', retention=30, dateext=False), want
        )
