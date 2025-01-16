# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit tests for the SMTP DKIM signing charm."""

import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

# We also need to mock up charms.layer so we can run unit tests without having
# to build the charm and pull in layers such as layer-status.
sys.modules['charms.layer'] = mock.MagicMock()

from charmhelpers.core import unitdata  # NOQA: E402
from charms.layer import status  # NOQA: E402

# Add path to where our reactive layer lives and import.
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__)))))
from reactive import smtp_dkim_signing  # NOQA: E402

# pylint: disable=unused-argument,protected-access,too-many-public-methods


class TestCharm(unittest.TestCase):
    def setUp(self):
        self.maxdiff = None
        self.tmpdir = tempfile.mkdtemp(prefix='charm-unittests-')
        self.addCleanup(shutil.rmtree, self.tmpdir)
        os.environ['UNIT_STATE_DB'] = os.path.join(self.tmpdir, '.unit-state.db')
        unitdata.kv().set('test', {})

        self.charm_dir = os.path.dirname(
            os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
        )

        patcher = mock.patch('charmhelpers.core.hookenv.log')
        mock_log = patcher.start()
        self.addCleanup(patcher.stop)
        mock_log.return_value = ""
        # Also needed for host.write_file()
        patcher = mock.patch('charmhelpers.core.host.log')
        mock_log = patcher.start()
        self.addCleanup(patcher.stop)
        mock_log.return_value = ""

        patcher = mock.patch('charmhelpers.core.hookenv.charm_dir')
        mock_charm_dir = patcher.start()
        self.addCleanup(patcher.stop)
        mock_charm_dir.return_value = self.charm_dir

        patcher = mock.patch('charmhelpers.core.hookenv.local_unit')
        mock_local_unit = patcher.start()
        self.addCleanup(patcher.stop)
        mock_local_unit.return_value = 'smtp-dkim-signing/0'

        patcher = mock.patch('charmhelpers.core.hookenv.config')
        self.mock_config = patcher.start()
        self.addCleanup(patcher.stop)
        self.mock_config.return_value = {
            'admin_email': "",
            'domains': 'myawsomedomain.local',
            'keytable': "",
            'mode': 'sv',
            'selector': '20210622',
            'signing_key': "",
            'signingtable': "",
            'trusted_sources': "",
        }

        patcher = mock.patch('charmhelpers.core.hookenv.open_port')
        self.mock_open_port = patcher.start()
        self.addCleanup(patcher.stop)

        patcher = mock.patch('charmhelpers.core.host.service_reload')
        self.mock_service_reload = patcher.start()
        self.addCleanup(patcher.stop)

        patcher = mock.patch('charmhelpers.core.host.service_restart')
        patcher.start()
        self.addCleanup(patcher.stop)

        patcher = mock.patch('charmhelpers.core.host.service_start')
        patcher.start()
        self.addCleanup(patcher.stop)

        patcher = mock.patch('charmhelpers.core.host.service_stop')
        patcher.start()
        self.addCleanup(patcher.stop)

        status.active.reset_mock()
        status.blocked.reset_mock()
        status.maintenance.reset_mock()

    @mock.patch('charms.reactive.clear_flag')
    def test_hook_upgrade_charm(self, clear_flag):
        smtp_dkim_signing.upgrade_charm()
        status.maintenance.assert_called()

        want = [
            mock.call('smtp-dkim-signing.active'),
            mock.call('smtp-dkim-signing.configured'),
            mock.call('smtp-dkim-signing.installed'),
        ]
        clear_flag.assert_has_calls(want, any_order=True)
        self.assertEqual(len(want), len(clear_flag.mock_calls))

    @mock.patch('charms.reactive.clear_flag')
    @mock.patch('charms.reactive.set_flag')
    def test_hook_install(self, set_flag, clear_flag):
        smtp_dkim_signing.install()

        want = [mock.call('smtp-dkim-signing.installed')]
        set_flag.assert_has_calls(want, any_order=True)
        self.assertEqual(len(want), len(set_flag.mock_calls))

        want = [mock.call('smtp-dkim-signing.active'), mock.call('smtp-dkim-signing.configured')]
        clear_flag.assert_has_calls(want, any_order=True)
        self.assertEqual(len(want), len(clear_flag.mock_calls))

    @mock.patch('charms.reactive.clear_flag')
    @mock.patch('reactive.smtp_dkim_signing._update_aliases')
    def test_hook_config_changed(self, update_aliases, clear_flag):
        smtp_dkim_signing.config_changed()
        want = [mock.call('smtp-dkim-signing.configured')]
        clear_flag.assert_has_calls(want, any_order=True)

    @mock.patch('charms.reactive.clear_flag')
    @mock.patch('charms.reactive.set_flag')
    def test_configure_smtp_dkim_signing_flags(self, set_flag, clear_flag):
        opendkim_conf_path = os.path.join(self.tmpdir, 'opendkim.conf')
        smtp_dkim_signing.configure_smtp_dkim_signing(opendkim_conf_path)

        want = [mock.call('smtp-dkim-signing.configured')]
        set_flag.assert_has_calls(want, any_order=True)
        self.assertEqual(len(want), len(set_flag.mock_calls))

        want = [
            mock.call('smtp-dkim-signing.active'), mock.call('smtp-dkim-signing.milter_notified')
        ]
        clear_flag.assert_has_calls(want, any_order=True)
        self.assertEqual(len(want), len(clear_flag.mock_calls))

    @mock.patch('charms.reactive.clear_flag')
    @mock.patch('charms.reactive.set_flag')
    @mock.patch('charmhelpers.core.hookenv.relation_ids')
    @mock.patch('charmhelpers.core.hookenv.relation_set')
    def test_configure_smtp_dkim_signing(self, relation_set, relation_ids, set_flag, clear_flag):
        opendkim_conf_path = os.path.join(self.tmpdir, 'opendkim.conf')

        relation_ids.return_value = ['milter:32']
        smtp_dkim_signing.configure_smtp_dkim_signing(opendkim_conf_path)

        with open(opendkim_conf_path, "r", encoding="utf-8") as f:
            got = f.read()
        with open('tests/unit/files/opendkim.conf', "r", encoding="utf-8") as f:
            want = f.read()
        self.assertEqual(want, got)

        self.mock_service_reload.assert_called()
        self.mock_open_port.assert_called_with(smtp_dkim_signing.OPENDKIM_MILTER_PORT, 'TCP')

    @mock.patch('charms.reactive.clear_flag')
    @mock.patch('charms.reactive.set_flag')
    @mock.patch('charmhelpers.core.hookenv.relation_ids')
    @mock.patch('charmhelpers.core.hookenv.relation_set')
    def test_configure_smtp_dkim_signing_domain_none(
        self, relation_set, relation_ids, set_flag, clear_flag
    ):
        opendkim_conf_path = os.path.join(self.tmpdir, 'opendkim.conf')

        relation_ids.return_value = ['milter:32']
        self.mock_config.return_value['domains'] = ""
        smtp_dkim_signing.configure_smtp_dkim_signing(opendkim_conf_path)

        with open(opendkim_conf_path, "r", encoding="utf-8") as f:
            got = f.read()
        with open('tests/unit/files/opendkim-domains-none.conf', "r", encoding="utf-8") as f:
            want = f.read()
        self.assertEqual(want, got)

    @mock.patch('charms.reactive.clear_flag')
    @mock.patch('charms.reactive.set_flag')
    @mock.patch('charmhelpers.core.hookenv.relation_ids')
    @mock.patch('charmhelpers.core.hookenv.relation_set')
    def test_configure_smtp_dkim_signing_domain_multi(
        self, relation_set, relation_ids, set_flag, clear_flag
    ):
        opendkim_conf_path = os.path.join(self.tmpdir, 'opendkim.conf')

        relation_ids.return_value = ['milter:32']
        self.mock_config.return_value['domains'] = (
            'mydomain1.local mydomain2.local,mydomain3.local'
        )
        smtp_dkim_signing.configure_smtp_dkim_signing(opendkim_conf_path)

        with open(opendkim_conf_path, "r", encoding="utf-8") as f:
            got = f.read()
        with open('tests/unit/files/opendkim-domains-multi.conf', "r", encoding="utf-8") as f:
            want = f.read()
        self.assertEqual(want, got)

    @mock.patch('charms.reactive.clear_flag')
    @mock.patch('charms.reactive.set_flag')
    @mock.patch('charmhelpers.core.hookenv.relation_ids')
    @mock.patch('charmhelpers.core.hookenv.relation_set')
    def test_configure_smtp_dkim_signing_key_auto(
        self, relation_set, relation_ids, set_flag, clear_flag
    ):
        opendkim_conf_path = os.path.join(self.tmpdir, 'opendkim.conf')

        self.mock_config.return_value['signing_key'] = 'auto'
        smtp_dkim_signing.configure_smtp_dkim_signing(opendkim_conf_path)

        status.blocked.assert_called_with(
            'Automatic generation of signing keys not implemented yet'
        )
        self.mock_service_reload.assert_not_called()
        self.mock_open_port.assert_not_called()

    @mock.patch('charms.reactive.clear_flag')
    @mock.patch('charms.reactive.set_flag')
    @mock.patch('charmhelpers.core.hookenv.relation_ids')
    @mock.patch('charmhelpers.core.hookenv.relation_set')
    def test_configure_smtp_dkim_signing_key_provided(
        self, relation_set, relation_ids, set_flag, clear_flag
    ):
        opendkim_conf_path = os.path.join(self.tmpdir, 'opendkim.conf')

        relation_ids.return_value = ['milter:32']
        with open('tests/unit/files/signing_key.private', "r", encoding="utf-8") as f:
            signing_key = f.read()
        self.mock_config.return_value['signing_key'] = signing_key
        smtp_dkim_signing.configure_smtp_dkim_signing(opendkim_conf_path, self.tmpdir)

        with open(opendkim_conf_path, "r", encoding="utf-8") as f:
            got = f.read()
        with open('tests/unit/files/opendkim.conf', "r", encoding="utf-8") as f:
            want = f.read()
        self.assertEqual(want, got)
        self.assertTrue(os.path.exists(os.path.join(self.tmpdir, '20210622.private')))
        with open(os.path.join(self.tmpdir, '20210622.private'), "r", encoding="utf-8") as f:
            got = f.read()
        want = signing_key
        self.assertEqual(want, got)

        self.mock_service_reload.assert_called()
        self.mock_open_port.assert_called_with(smtp_dkim_signing.OPENDKIM_MILTER_PORT, 'TCP')

    @mock.patch('charms.reactive.clear_flag')
    @mock.patch('charms.reactive.set_flag')
    @mock.patch('charmhelpers.core.hookenv.relation_ids')
    @mock.patch('charmhelpers.core.hookenv.relation_set')
    def test_configure_smtp_dkim_signing_key_provided_invalid(
        self, relation_set, relation_ids, set_flag, clear_flag
    ):
        opendkim_conf_path = os.path.join(self.tmpdir, 'opendkim.conf')

        relation_ids.return_value = ['milter:32']
        self.mock_config.return_value['signing_key'] = 'someinvalidkey'
        smtp_dkim_signing.configure_smtp_dkim_signing(opendkim_conf_path, self.tmpdir)

        self.assertFalse(os.path.exists(os.path.join(self.tmpdir, '20210622.private')))
        status.blocked.assert_called_with('Invalid signing key provided')
        self.mock_service_reload.assert_not_called()
        self.mock_open_port.assert_not_called()

    @mock.patch('charms.reactive.clear_flag')
    @mock.patch('charms.reactive.set_flag')
    @mock.patch('charmhelpers.core.hookenv.relation_ids')
    @mock.patch('charmhelpers.core.hookenv.relation_set')
    def test_configure_smtp_dkim_signing_keytable(
        self, relation_set, relation_ids, set_flag, clear_flag
    ):
        opendkim_conf_path = os.path.join(self.tmpdir, 'opendkim.conf')
        keytable_path = os.path.join(self.tmpdir, 'keytable')

        relation_ids.return_value = ['milter:32']
        with open('tests/unit/files/keytable', "r", encoding="utf-8") as f:
            keytable = f.read()
        self.mock_config.return_value['keytable'] = keytable
        smtp_dkim_signing.configure_smtp_dkim_signing(opendkim_conf_path, self.tmpdir)
        with open(opendkim_conf_path, "r", encoding="utf-8") as f:
            got = f.read()
        with open('tests/unit/files/opendkim-keytable.conf', "r", encoding="utf-8") as f:
            want = f.read().format(keytable_path=keytable_path)
        self.assertEqual(want, got)

        with open(keytable_path, "r", encoding="utf-8") as f:
            got = f.read()
        want = smtp_dkim_signing.JUJU_HEADER + keytable + "\n"
        self.assertEqual(want, got)

    @mock.patch('charms.reactive.clear_flag')
    @mock.patch('charms.reactive.set_flag')
    @mock.patch('charmhelpers.core.hookenv.relation_ids')
    @mock.patch('charmhelpers.core.hookenv.relation_set')
    def test_configure_smtp_dkim_signing_signingtable(
        self, relation_set, relation_ids, set_flag, clear_flag
    ):
        opendkim_conf_path = os.path.join(self.tmpdir, 'opendkim.conf')
        signingtable_path = os.path.join(self.tmpdir, 'signingtable')

        relation_ids.return_value = ['milter:32']
        with open('tests/unit/files/signingtable', "r", encoding="utf-8") as f:
            signingtable = f.read()
        self.mock_config.return_value['signingtable'] = signingtable
        smtp_dkim_signing.configure_smtp_dkim_signing(opendkim_conf_path, self.tmpdir)
        with open(opendkim_conf_path, "r", encoding="utf-8") as f:
            got = f.read()
        with open('tests/unit/files/opendkim-signingtable.conf', "r", encoding="utf-8") as f:
            want = f.read().format(signingtable_path=signingtable_path)
        self.assertEqual(want, got)

        with open(signingtable_path, "r", encoding="utf-8") as f:
            got = f.read()
        want = smtp_dkim_signing.JUJU_HEADER + signingtable + "\n"
        self.assertEqual(want, got)

    @mock.patch('charms.reactive.clear_flag')
    @mock.patch('charms.reactive.set_flag')
    @mock.patch('charmhelpers.core.hookenv.relation_ids')
    @mock.patch('charmhelpers.core.hookenv.relation_set')
    def test_configure_smtp_dkim_signing_both_keytable_signingtable(
        self, relation_set, relation_ids, set_flag, clear_flag
    ):
        opendkim_conf_path = os.path.join(self.tmpdir, 'opendkim.conf')
        keytable_path = os.path.join(self.tmpdir, 'keytable')
        signingtable_path = os.path.join(self.tmpdir, 'signingtable')

        relation_ids.return_value = ['milter:32']
        with open('tests/unit/files/keytable', "r", encoding="utf-8") as f:
            keytable = f.read()
        self.mock_config.return_value['keytable'] = keytable
        with open('tests/unit/files/signingtable', "r", encoding="utf-8") as f:
            signingtable = f.read()
        self.mock_config.return_value['signingtable'] = signingtable
        smtp_dkim_signing.configure_smtp_dkim_signing(opendkim_conf_path, self.tmpdir)
        with open(opendkim_conf_path, "r", encoding="utf-8") as f:
            got = f.read()
        with open(
            'tests/unit/files/opendkim-both-keytable-signingtable.conf', "r", encoding="utf-8"
        ) as f:
            want = f.read().format(
                keytable_path=keytable_path, signingtable_path=signingtable_path
            )
        self.assertEqual(want, got)

    @mock.patch('charms.reactive.clear_flag')
    @mock.patch('charms.reactive.set_flag')
    @mock.patch('charmhelpers.core.hookenv.relation_ids')
    def test_configure_smtp_dkim_signing_no_change(self, relation_ids, set_flag, clear_flag):
        opendkim_conf_path = os.path.join(self.tmpdir, 'opendkim.conf')
        smtp_dkim_signing.configure_smtp_dkim_signing(opendkim_conf_path)

        self.mock_service_reload.reset_mock()
        self.mock_open_port.reset_mock()

        # Call it again, should be no change, so no need to reload services.
        smtp_dkim_signing.configure_smtp_dkim_signing(opendkim_conf_path)

        self.mock_service_reload.assert_not_called()

    @mock.patch('charms.reactive.clear_flag')
    @mock.patch('charms.reactive.set_flag')
    @mock.patch('charmhelpers.core.hookenv.relation_ids')
    @mock.patch('charmhelpers.core.hookenv.relation_set')
    def test_configure_smtp_dkim_signing_mode_sign_only(
        self, relation_set, relation_ids, set_flag, clear_flag
    ):
        opendkim_conf_path = os.path.join(self.tmpdir, 'opendkim.conf')

        relation_ids.return_value = ['milter:32']
        self.mock_config.return_value['mode'] = 's'
        smtp_dkim_signing.configure_smtp_dkim_signing(opendkim_conf_path)

        with open(opendkim_conf_path, "r", encoding="utf-8") as f:
            got = f.read()
        with open('tests/unit/files/opendkim-mode-s.conf', "r", encoding="utf-8") as f:
            want = f.read()
        self.assertEqual(want, got)

        self.mock_service_reload.assert_called()
        self.mock_open_port.assert_called_with(smtp_dkim_signing.OPENDKIM_MILTER_PORT, 'TCP')

    @mock.patch('charms.reactive.clear_flag')
    @mock.patch('charms.reactive.set_flag')
    @mock.patch('charmhelpers.core.hookenv.relation_ids')
    @mock.patch('charmhelpers.core.hookenv.relation_set')
    def test_configure_smtp_dkim_signing_mode_verify_only(
        self, relation_set, relation_ids, set_flag, clear_flag
    ):
        opendkim_conf_path = os.path.join(self.tmpdir, 'opendkim.conf')

        relation_ids.return_value = ['milter:32']
        self.mock_config.return_value['mode'] = 'v'
        smtp_dkim_signing.configure_smtp_dkim_signing(opendkim_conf_path)

        with open(opendkim_conf_path, "r", encoding="utf-8") as f:
            got = f.read()
        with open('tests/unit/files/opendkim-mode-v.conf', "r", encoding="utf-8") as f:
            want = f.read()
        self.assertEqual(want, got)

        self.mock_service_reload.assert_called()
        self.mock_open_port.assert_called_with(smtp_dkim_signing.OPENDKIM_MILTER_PORT, 'TCP')

    @mock.patch('charms.reactive.clear_flag')
    @mock.patch('charms.reactive.set_flag')
    def test_hook_relation_milter_flags(self, set_flag, clear_flag):
        smtp_dkim_signing.milter_relation_changed()

        want = [mock.call('smtp-dkim-signing.milter_notified')]
        clear_flag.assert_has_calls(want, any_order=True)
        self.assertEqual(len(want), len(clear_flag.mock_calls))

        set_flag.assert_not_called()

    @mock.patch('charms.reactive.clear_flag')
    @mock.patch('charms.reactive.set_flag')
    @mock.patch('charmhelpers.core.hookenv.relation_ids')
    @mock.patch('charmhelpers.core.hookenv.relation_set')
    def test_milter_notify(self, relation_set, relation_ids, set_flag, clear_flag):
        relation_ids.return_value = ['milter:32']
        smtp_dkim_signing.milter_notify()
        want = {'port': smtp_dkim_signing.OPENDKIM_MILTER_PORT}
        relation_set.assert_called_with(relation_id='milter:32', relation_settings=want)

    @mock.patch('charms.reactive.clear_flag')
    @mock.patch('charms.reactive.set_flag')
    @mock.patch('charmhelpers.core.hookenv.relation_ids')
    @mock.patch('charmhelpers.core.hookenv.relation_set')
    def test_milter_notify_flags(self, relation_set, relation_ids, set_flag, clear_flag):
        smtp_dkim_signing.milter_notify()

        want = [mock.call('smtp-dkim-signing.milter_notified')]
        set_flag.assert_has_calls(want, any_order=True)
        self.assertEqual(len(want), len(set_flag.mock_calls))

        want = [mock.call('smtp-dkim-signing.active')]
        clear_flag.assert_has_calls(want, any_order=True)
        self.assertEqual(len(want), len(clear_flag.mock_calls))

    @mock.patch('charms.reactive.set_flag')
    def test_set_active(self, set_flag):
        smtp_dkim_signing.set_active()
        status.active.assert_called_once_with('Ready')
        set_flag.assert_called_once_with('smtp-dkim-signing.active')

    @mock.patch('charms.reactive.set_flag')
    def test_set_active_revno(self, set_flag):
        # git - "uax4glw"
        smtp_dkim_signing.set_active(os.path.join(self.charm_dir, 'tests/unit/files/version'))
        status.active.assert_called_once_with('Ready (source version/commit uax4glw)')

    @mock.patch('charms.reactive.set_flag')
    def test_set_active_shortened_revno(self, set_flag):
        smtp_dkim_signing.set_active(os.path.join(self.charm_dir, 'tests/unit/files/version_long'))
        status.active.assert_called_once_with('Ready (source version/commit somerand…)')

    @mock.patch('charms.reactive.set_flag')
    def test_set_active_dirty_revno(self, set_flag):
        smtp_dkim_signing.set_active(
            os.path.join(self.charm_dir, 'tests/unit/files/version_dirty')
        )
        status.active.assert_called_once_with('Ready (source version/commit 38c901f-dirty)')

    def test__write_file(self):
        source = '# User-provided config added here'
        dest = os.path.join(self.tmpdir, 'my-test-file')

        self.assertTrue(smtp_dkim_signing._write_file(source, dest))
        # Write again, should return False and not True per above.
        self.assertFalse(smtp_dkim_signing._write_file(source, dest))

        # Check contents
        with open(dest, "r", encoding="utf-8") as f:
            got = f.read()
        self.assertEqual(got, source)

    @mock.patch('subprocess.call')
    def test__update_aliases(self, call):
        dest = os.path.join(self.tmpdir, 'aliases')

        # Empty, does not exist.
        smtp_dkim_signing._update_aliases("", dest)
        want = 'devnull:       /dev/null\n'
        with open(dest, "r", encoding="utf-8") as f:
            got = f.read()
        self.assertEqual(want, got)
        call.assert_called_with(["newaliases"])

        # Has something prepopulated, but not devnull.
        call.reset_mock()
        content = 'postmaster:    root\n'
        with open(dest, "w", encoding="utf-8") as f:
            f.write(content)
        smtp_dkim_signing._update_aliases("", dest)
        want = content + 'devnull:       /dev/null\n'
        with open(dest, "r", encoding="utf-8") as f:
            got = f.read()
        self.assertEqual(want, got)
        call.assert_called_with(["newaliases"])

        # Has devnull, so do nothing and do not call newaliases.
        call.reset_mock()
        content = 'postmaster:    root\ndevnull:       /dev/null\n'
        with open(dest, "w", encoding="utf-8") as f:
            f.write(content)
        smtp_dkim_signing._update_aliases("", dest)
        want = content
        with open(dest, "r", encoding="utf-8") as f:
            got = f.read()
        self.assertEqual(want, got)
        call.assert_not_called()

        # Admin email set.
        call.reset_mock()
        content = 'postmaster:    root\ndevnull:       /dev/null\n'
        with open(dest, "w", encoding="utf-8") as f:
            f.write(content)
        smtp_dkim_signing._update_aliases('root@admin.mydomain.local', dest)
        want = (
            "postmaster:    root\ndevnull:       /dev/null\n"
            "root:          root@admin.mydomain.local\n"
        )
        with open(dest, "r", encoding="utf-8") as f:
            got = f.read()
        self.assertEqual(want, got)
        call.assert_called_with(["newaliases"])

        # Has admin email, so do nothing and do not call newaliases.
        call.reset_mock()
        content = (
            "postmaster:    root\ndevnull:       /dev/null\n"
            "root:          root@admin.mydomain.local\n"
        )
        with open(dest, "w", encoding="utf-8") as f:
            f.write(content)
        smtp_dkim_signing._update_aliases('root@admin.mydomain.local', dest)
        want = content
        with open(dest, "r", encoding="utf-8") as f:
            got = f.read()
        self.assertEqual(want, got)
        call.assert_not_called()
