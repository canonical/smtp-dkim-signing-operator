# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""SMTP DKIM signing charm."""

import grp
import os
import pwd
import subprocess  # nosec

import jinja2
from charmhelpers.core import hookenv, host
from charms import reactive
from charms.layer import status

from lib import utils

JUJU_HEADER = "# This file is Juju managed - do not edit by hand #\n\n"
OPENDKIM_CONF_PATH = "/etc/opendkim.conf"
OPENDKIM_KEYS_PATH = "/etc/dkimkeys"
OPENDKIM_MILTER_PORT = 8892

# https://datatracker.ietf.org/doc/html/rfc6376#section-5.4
DEFAULT_SIGN_HEADERS = (
    "From,Reply-To,Subject,Date,To,Cc"
    ",Resent-From,Resent-Date,Resent-To,Resent-Cc"
    ",In-Reply-To,References"
    ",MIME-Version,Message-ID,Content-Type"
)


@reactive.hook("upgrade-charm")
def upgrade_charm() -> None:
    status.maintenance("forcing reconfiguration on upgrade-charm")
    reactive.clear_flag("smtp-dkim-signing.active")
    reactive.clear_flag("smtp-dkim-signing.configured")
    reactive.clear_flag("smtp-dkim-signing.installed")


@reactive.when_not("smtp-dkim-signing.installed")
def install() -> None:
    reactive.clear_flag("smtp-dkim-signing.active")
    reactive.clear_flag("smtp-dkim-signing.configured")
    reactive.set_flag("smtp-dkim-signing.installed")


@reactive.when_any(
    "config.changed.admin_email",
    "config.changed.domains",
    "config.changed.keytable",
    "config.changed.selector",
    "config.changed.signingtable",
    "config.changed.trusted_sources",
)
def config_changed() -> None:
    reactive.clear_flag("smtp-dkim-signing.configured")

    config = hookenv.config()
    _update_aliases(config["admin_email"])


@reactive.when("config.changed.log_retention")
def update_logrotate(logrotate_conf_path: str = "/etc/logrotate.d/rsyslog") -> None:
    reactive.clear_flag("smtp-dkim-signing.active")
    status.maintenance("Updating log retention / rotation configs")

    config = hookenv.config()
    retention = config["log_retention"]
    contents = utils.update_logrotate_conf(
        logrotate_conf_path, frequency="daily", retention=retention
    )
    _write_file(contents, logrotate_conf_path)


@reactive.when("smtp-dkim-signing.installed")
@reactive.when_not("smtp-dkim-signing.configured")
def configure_smtp_dkim_signing(
    dkim_conf_path: str = OPENDKIM_CONF_PATH, dkim_keys_dir: str = OPENDKIM_KEYS_PATH
) -> None:
    status.maintenance("Setting up SMTP DKIM Signing")
    reactive.clear_flag("smtp-dkim-signing.active")
    reactive.clear_flag("smtp-dkim-signing.milter_notified")

    config = hookenv.config()

    mode = config["mode"]
    signing_mode = "s" in mode

    keyfile = os.path.join(dkim_keys_dir, f"{os.path.basename(config['selector'])}.private")
    signing_key = config.get("signing_key", "")
    if signing_key == "auto":
        # With automatic key generation, the leader unit needs to generate
        # and then distribute it out to the peers.
        #   $ opendkim-genkey -t -s $SELECTOR -d $DOMAIN
        status.blocked("Automatic generation of signing keys not implemented yet")
        return
    if signing_key.startswith("-----BEGIN RSA PRIVATE KEY-----") and signing_key.strip().endswith(
        "-----END RSA PRIVATE KEY-----"
    ):
        _write_file(signing_key, keyfile)
    # "" means manually provide or provide signing key via other means.
    elif signing_key != "" and signing_mode:
        status.blocked("Invalid signing key provided")
        return

    domains = "*"
    if config["domains"]:
        # Support both space and comma-separated list of domains.
        domains = ",".join(config["domains"].split())

    keytable_path = os.path.join(dkim_keys_dir, "keytable")
    if config["keytable"] and not config["keytable"].startswith("MANUAL"):
        contents = JUJU_HEADER + config["keytable"] + "\n"
        _write_file(contents, keytable_path)
    signingtable_path = os.path.join(dkim_keys_dir, "signingtable")
    if config["signingtable"] and not config["signingtable"].startswith("MANUAL"):
        contents = JUJU_HEADER + config["signingtable"] + "\n"
        _write_file(contents, signingtable_path)

    context = {
        "JUJU_HEADER": JUJU_HEADER,
        "canonicalization": "relaxed/relaxed",
        "domains": domains,
        "internalhosts": config["trusted_sources"] or "0.0.0.0/0",
        "keyfile": os.path.join(OPENDKIM_KEYS_PATH, f"{config['selector']}.private"),
        "keytable": keytable_path if config["keytable"] else "",
        "mode": mode,
        "selector": config["selector"],
        "signing_mode": signing_mode,
        "signheaders": DEFAULT_SIGN_HEADERS,
        "signingtable": signingtable_path if config["signingtable"] else "",
        "socket": f"inet:{OPENDKIM_MILTER_PORT}",
    }
    base = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
    env = jinja2.Environment(loader=jinja2.FileSystemLoader(base))  # nosec
    template = env.get_template("templates/opendkim_conf.tmpl")
    contents = template.render(context)
    if _write_file(contents, dkim_conf_path):
        host.service_reload("opendkim")
    # Ensure service is running.
    host.service_start("opendkim")
    hookenv.open_port(OPENDKIM_MILTER_PORT, "TCP")

    reactive.set_flag("smtp-dkim-signing.configured")


@reactive.hook("milter-relation-joined", "milter-relation-changed")
def milter_relation_changed() -> None:
    reactive.clear_flag("smtp-dkim-signing.milter_notified")


@reactive.when("smtp-dkim-signing.configured")
@reactive.when_not("smtp-dkim-signing.milter_notified")
def milter_notify() -> None:
    reactive.clear_flag("smtp-dkim-signing.active")
    status.maintenance("Notifying related applications of updated settings")

    relation_settings = {
        "port": OPENDKIM_MILTER_PORT,
    }
    for rid in hookenv.relation_ids("milter"):
        hookenv.relation_set(relation_id=rid, relation_settings=relation_settings)

    reactive.set_flag("smtp-dkim-signing.milter_notified")


@reactive.when("smtp-dkim-signing.configured")
@reactive.when_not("smtp-dkim-signing.active")
def set_active(version_file: str = "version") -> None:
    revision = ""
    if os.path.exists(version_file):
        with open(version_file, encoding="utf-8") as f:
            line = f.readline().strip()
        # We only want the first 8 characters, that's enough to tell
        # which version of the charm we're using. But include the
        # entire version if it's 'dirty' according to charm build.
        if len(line) > 8 and not line == line[:7] + "-dirty":
            revision = f" (source version/commit {line[:8]}…)"
        else:
            revision = f" (source version/commit {line})"

    status.active(f"Ready{revision}")
    reactive.set_flag("smtp-dkim-signing.active")


def _write_file(source: str, dest_path: str) -> bool:
    """Write file only on changes and return True if changes written."""
    # Compare and only write out file on change.
    dest = ""
    if not os.path.exists(dest_path):
        with open(dest_path, "a", encoding="utf-8") as f:
            os.utime(dest_path, None)
    try:
        with open(dest_path, "r", encoding="utf-8") as f:
            dest = f.read()
        if source == dest:
            return False
    except FileNotFoundError:
        pass

    owner = pwd.getpwuid(os.getuid()).pw_name
    group = grp.getgrgid(os.getgid()).gr_name

    host.write_file(path=dest_path + ".new", content=source, perms=0o644, owner=owner, group=group)
    os.rename(dest_path + ".new", dest_path)
    return True


def _update_aliases(admin_email: str = "", aliases_path: str = "/etc/aliases") -> None:

    aliases = []
    try:
        with open(aliases_path, "r", encoding="utf-8") as f:
            aliases = f.readlines()
    except FileNotFoundError:
        pass

    add_devnull = True
    new_aliases = []
    for line in aliases:
        if line.startswith("devnull:"):
            add_devnull = False
        if line.startswith("root:"):
            continue
        new_aliases.append(line)

    if add_devnull:
        new_aliases.append("devnull:       /dev/null\n")
    if admin_email:
        new_aliases.append(f"root:          {admin_email}\n")

    changed = _write_file("".join(new_aliases), aliases_path)
    if changed:
        subprocess.call(["newaliases"])  # nosec
