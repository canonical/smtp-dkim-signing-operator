import grp
import os
import pwd
import subprocess  # nosec

import jinja2

from charms import reactive
from charms.layer import status
from charmhelpers.core import hookenv, host

from lib import utils


JUJU_HEADER = '# This file is Juju managed - do not edit by hand #\n\n'
OPENDKIM_CONF_PATH = '/etc/opendkim.conf'
OPENDKIM_KEYS_PATH = '/etc/dkimkeys'
OPENDKIM_MILTER_PORT = 8892

# https://datatracker.ietf.org/doc/html/rfc6376#section-5.4
DEFAULT_SIGN_HEADERS = (
    'From,Reply-To,Subject,Date,To,Cc'
    ',Resent-From,Resent-Date,Resent-To,Resent-Cc'
    ',In-Reply-To,References'
    ',MIME-Version,Message-ID,Content-Type'
)


@reactive.hook('upgrade-charm')
def upgrade_charm():
    status.maintenance('forcing reconfiguration on upgrade-charm')
    reactive.clear_flag('smtp-dkim-signing.active')
    reactive.clear_flag('smtp-dkim-signing.configured')
    reactive.clear_flag('smtp-dkim-signing.installed')


@reactive.when_not('smtp-dkim-signing.installed')
def install():
    reactive.clear_flag('smtp-dkim-signing.active')
    reactive.clear_flag('smtp-dkim-signing.configured')
    reactive.set_flag('smtp-dkim-signing.installed')


@reactive.when_any(
    'config.changed.admin_email',
    'config.changed.domains',
    'config.changed.keytable',
    'config.changed.selector',
    'config.changed.signingtable',
    'config.changed.trusted_sources',
)
def config_changed():
    reactive.clear_flag('smtp-dkim-signing.configured')

    config = hookenv.config()
    _update_aliases(config['admin_email'])


@reactive.when('config.changed.log_retention')
def update_logrotate(logrotate_conf_path='/etc/logrotate.d/rsyslog'):
    reactive.clear_flag('smtp-dkim-signing.active')
    status.maintenance('Updating log retention / rotation configs')

    config = hookenv.config()
    retention = config['log_retention']
    contents = utils.update_logrotate_conf(logrotate_conf_path, frequency='daily', retention=retention)
    _write_file(contents, logrotate_conf_path)


@reactive.when('smtp-dkim-signing.installed')
@reactive.when_not('smtp-dkim-signing.configured')
def configure_smtp_dkim_signing(dkim_conf_path=OPENDKIM_CONF_PATH, dkim_keys_dir=OPENDKIM_KEYS_PATH):
    status.maintenance('Setting up SMTP DKIM Signing')
    reactive.clear_flag('smtp-dkim-signing.active')
    reactive.clear_flag('smtp-dkim-signing.milter_notified')

    config = hookenv.config()

    mode = config['mode']
    signing_mode = 's' in mode

    keyfile = os.path.join(dkim_keys_dir, '{}.private'.format(os.path.basename(config['selector'])))
    signing_key = config.get('signing_key', '')
    if signing_key == 'auto':
        # With automatic key generation, the leader unit needs to generate
        # and then distribute it out to the peers.
        #   $ opendkim-genkey -t -s $SELECTOR -d $DOMAIN
        status.blocked('Automatic generation of signing keys not implemented yet')
        return
    elif signing_key.startswith('-----BEGIN RSA PRIVATE KEY-----') and signing_key.strip().endswith(
        '-----END RSA PRIVATE KEY-----'
    ):
        _write_file(signing_key, keyfile)
    # '' means manually provide or provide signing key via other means.
    elif signing_key != '' and signing_mode:
        status.blocked('Invalid signing key provided')
        return

    domains = '*'
    if config['domains']:
        # Support both space and comma-separated list of domains.
        domains = ','.join(config['domains'].split())

    keytable_path = os.path.join(dkim_keys_dir, 'keytable')
    if config['keytable'] and not config['keytable'].startswith('MANUAL'):
        contents = JUJU_HEADER + config['keytable'] + '\n'
        _write_file(contents, keytable_path)
    signingtable_path = os.path.join(dkim_keys_dir, 'signingtable')
    if config['signingtable'] and not config['signingtable'].startswith('MANUAL'):
        contents = JUJU_HEADER + config['signingtable'] + '\n'
        _write_file(contents, signingtable_path)

    context = {
        'JUJU_HEADER': JUJU_HEADER,
        'canonicalization': 'relaxed/relaxed',
        'domains': domains,
        'internalhosts': config['trusted_sources'] or '0.0.0.0/0',
        'keyfile': os.path.join(OPENDKIM_KEYS_PATH, '{}.private'.format(config['selector'])),
        'keytable': keytable_path if config['keytable'] else '',
        'mode': mode,
        'selector': config['selector'],
        'signing_mode': signing_mode,
        'signheaders': DEFAULT_SIGN_HEADERS,
        'signingtable': signingtable_path if config['signingtable'] else '',
        'socket': 'inet:{}'.format(OPENDKIM_MILTER_PORT),
    }
    base = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
    env = jinja2.Environment(loader=jinja2.FileSystemLoader(base))  # nosec
    template = env.get_template('templates/opendkim_conf.tmpl')
    contents = template.render(context)
    if _write_file(contents, dkim_conf_path):
        host.service_reload('opendkim')
    # Ensure service is running.
    host.service_start('opendkim')

    # XXX: If/when we make the port a config option, we'll want to
    # open the new port, then make sure the old port is closed.
    hookenv.open_port(OPENDKIM_MILTER_PORT, 'TCP')

    reactive.set_flag('smtp-dkim-signing.configured')


@reactive.hook('milter-relation-joined', 'milter-relation-changed')
def milter_relation_changed():
    reactive.clear_flag('smtp-dkim-signing.milter_notified')


@reactive.when('smtp-dkim-signing.configured')
@reactive.when_not('smtp-dkim-signing.milter_notified')
def milter_notify():
    reactive.clear_flag('smtp-dkim-signing.active')
    status.maintenance('Notifying related applications of updated settings')

    relation_settings = {
        'port': OPENDKIM_MILTER_PORT,
    }
    for rid in hookenv.relation_ids('milter'):
        hookenv.relation_set(relation_id=rid, relation_settings=relation_settings)

    reactive.set_flag('smtp-dkim-signing.milter_notified')


@reactive.when('smtp-dkim-signing.configured')
@reactive.when_not('smtp-dkim-signing.active')
def set_active(version_file='version'):
    revision = ''
    if os.path.exists(version_file):
        with open(version_file) as f:
            line = f.readline().strip()
        # We only want the first 8 characters, that's enough to tell
        # which version of the charm we're using. But include the
        # entire version if it's 'dirty' according to charm build.
        if len(line) > 8 and not line == line[:7] + '-dirty':
            revision = ' (source version/commit {}…)'.format(line[:8])
        else:
            revision = ' (source version/commit {})'.format(line)

    status.active('Ready{}'.format(revision))
    reactive.set_flag('smtp-dkim-signing.active')


def _copy_file(source_path, dest_path, **kwargs):
    with open(source_path, 'r') as f:
        source = f.read()
    return _write_file(source, dest_path, **kwargs)


def _write_file(source, dest_path, perms=0o644, owner=None, group=None):
    """Write file only on changes and return True if changes written."""
    # Compare and only write out file on change.
    dest = ''
    if not os.path.exists(dest_path):
        with open(dest_path, 'a') as f:
            os.utime(dest_path, None)
    try:
        with open(dest_path, 'r') as f:
            dest = f.read()
        if source == dest:
            return False
    except FileNotFoundError:
        pass

    if owner is None:
        owner = pwd.getpwuid(os.getuid()).pw_name
    if group is None:
        group = grp.getgrgid(os.getgid()).gr_name

    host.write_file(path=dest_path + '.new', content=source, perms=perms, owner=owner, group=group)
    os.rename(dest_path + '.new', dest_path)
    return True


def _update_aliases(admin_email='', aliases_path='/etc/aliases'):

    aliases = []
    try:
        with open(aliases_path, 'r') as f:
            aliases = f.readlines()
    except FileNotFoundError:
        pass

    add_devnull = True
    new_aliases = []
    for line in aliases:
        if line.startswith('devnull:'):
            add_devnull = False
        if line.startswith('root:'):
            continue
        new_aliases.append(line)

    if add_devnull:
        new_aliases.append('devnull:       /dev/null\n')
    if admin_email:
        new_aliases.append('root:          {}\n'.format(admin_email))

    changed = _write_file(''.join(new_aliases), aliases_path)
    if changed:
        subprocess.call(['newaliases'])  # nosec

    return
