#!/usr/bin/env python3

# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Integration tests."""

import logging
import pathlib
import smtplib
import socket
import subprocess  # nosec B404
import tempfile
import time

import jubilant
import pytest
import requests

logger = logging.getLogger(__name__)


def generate_opendkim_genkey(domain: str, selector: str) -> (str, str):
    """Generate dkim txt record and private key for a domain an selector."""
    with tempfile.TemporaryDirectory() as tmpdirname:
        logger.info("JAVI TEMPDIR: %s", tmpdirname)
        subprocess.run(  # nosec
            ["opendkim-genkey", "-s", selector, "-d", domain], check=True, cwd=tmpdirname
        )
        # Two files should have been created, {selector}.txt and {selector}.private
        txt_data = (pathlib.Path(tmpdirname) / pathlib.Path(f"{selector}.txt")).read_text()
        private_data = (pathlib.Path(tmpdirname) / pathlib.Path(f"{selector}.private")).read_text()
        return txt_data, private_data


@pytest.fixture(scope="session", name="machine_ip_address")
def machine_ip_address_fixture() -> str:
    """IP address for the machine running the tests."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip_address = s.getsockname()[0]
    logger.info("IP Address for the current test runner: %s", ip_address)
    s.close()
    return ip_address


@pytest.mark.abort_on_fail
def test_simple_relay_dkim(
    juju: jubilant.Juju, smtp_dkim_signing_app, smtp_relay_app, machine_ip_address
):
    """
    arrange: Deploy smtp-relay charm with the testrelay.internal domain in relay domains.
    act: Send an email to an address with the testrelay.internal domain.
    assert: The email is correctly relayed to the mailcatcher local test smtp server.
    """
    status = juju.status()
    unit = list(status.apps[smtp_relay_app].units.values())[0]
    unit_ip = unit.public_address

    dkim_unit = list(status.apps[smtp_dkim_signing_app].units.keys())[0]

    domain = "testrelay.internal"
    selector = "default"
    _, private_key = generate_opendkim_genkey(domain=domain, selector=selector)
    with tempfile.NamedTemporaryFile(dir=".") as tf:
        tf.write(private_key.encode("utf-8"))
        tf.flush()
        juju.scp(tf.name, f"{dkim_unit}:/tmp/{domain}-{selector}.private")
        juju.exec(
            f"mv /tmp/{domain}-{selector}.private /etc/dkimkeys/; chown -R opendkim: /etc/dkimkeys/; chmod -R go-rwx /etc/dkimkeys/",
            unit=dkim_unit,
        )

    juju.config(
        smtp_dkim_signing_app,
        {
            "selector": selector,
            "keytable": f"{selector}._domainkey.{domain} {domain}:{selector}:/etc/dkimkeys/{domain}-{selector}.private",
            "signingtable": f"*@{domain} {selector}._domainkey.{domain}",
        },
    )

    # The charm does not restart opendkim on changes in the config values. This is a bug.
    juju.exec("systemctl restart opendkim", unit=dkim_unit)

    command_to_put_domain = (
        f"echo {machine_ip_address} {domain} | sudo tee -a /etc/hosts"
    )
    juju.exec(machine=unit.machine, command=command_to_put_domain)

    juju.config(smtp_relay_app, {"relay_domains": f"- {domain}"})
    juju.wait(
        lambda status: status.apps[smtp_relay_app].is_active,
        error=jubilant.any_blocked,
        timeout=6 * 60,
    )

    mailcatcher_url = "http://127.0.0.1:1080/messages"
    messages = requests.get(mailcatcher_url, timeout=5).json()
    # There should not be any message in mailcatcher before the test.
    assert len(messages) == 0

    with smtplib.SMTP(unit_ip) as server:
        server.set_debuglevel(2)
        from_addr = f"Some One <someone@{domain}>"
        to_addrs = [f"otherone@{domain}"]
        message = f"""\
Subject: Hi Mailtrap
To: {from_addr}
From: {to_addrs[0]}
This is my first message with Python."""
        server.sendmail(from_addr=from_addr, to_addrs=to_addrs, msg=message)

    for _ in range(5):
        messages = requests.get(mailcatcher_url, timeout=5).json()
        if messages:
            break
        time.sleep(1)
    assert len(messages) == 1
    message = requests.get(f"{mailcatcher_url}/{messages[0]['id']}.source", timeout=5).text
    logger.info("Message in mailcatcher: %s", message)
    assert f"DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d={domain}" in message

    # Clean up mailcatcher
    requests.delete(f"{mailcatcher_url}/{messages[0]['id']}", timeout=5)
