# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""State unit tests."""

import pytest

from reactive import state

@pytest.mark.parametrize(
    "charm_config",
    [
        (
            {
                "admin_email": "sample@email.com",
                "mode": "s",
                "selector": "mail",
            }
        ),
        (
            {
                "admin_email": "sample@email.com",
                "domains": "exaple.com,example2.com",
                "mode": "v",
                "selector": "mail",
                "signing_key": "validkey",
                "signingtable": "validtable",
                "trusted_sources": "10.0.0.1,10.0.0.2",
            }
        ),
        (
            {
                "admin_email": "sample@email.com",
                "domains": "exaple.com",
                "mode": "sv",
                "selector": "other",
                "signing_key": "validkey",
                "signingtable": "validtable",
                "trusted_sources": "10.0.0.1",
            }
        ),
    ],
)
def test_valid_state(charm_config):
    """
    arrange: do nothing.
    act: initialize a charm state from valid configuration.
    assert: the state values are parsed correctly.
    """
    charm_state = state.State.from_charm(config=charm_config)

    assert charm_state.admin_email == charm_config.get("admin_email")
    assert charm_state.domains == (
        charm_config.get("domains").split(",") if charm_config.get("domains") else []
    )
    assert charm_state.keytable == charm_config.get("keytable")
    assert charm_state.mode == charm_config.get("mode")
    assert charm_state.selector == charm_config.get("selector")
    assert charm_state.signing_key == charm_config.get("signing_key")
    assert charm_state.signingtable == charm_config.get("signingtable")
    assert charm_state.trusted_sources == (
        charm_config.get("trusted_sources").split(",") if charm_config.get("trusted_sources") else ["0.0.0.0/0"]
    )


@pytest.mark.parametrize(
    "charm_config",
    [
        (
            {
                "admin_email": "sampleemail.com",
                "mode": "s",
                "selector": "mail",
            }
        ),
        (
            {
                "admin_email": "sample@email.com",
                "mode": "as",
                "selector": "mail",
            }
        ),
        (
            {
                "admin_email": "sample@email.com",
                "domains": "@_",
                "mode": "sv",
            }
        ),
    ],
)
def test_invalid_state(charm_config):
    """
    arrange: do nothing.
    act: initialize a charm state from invalid configuration.
    assert: a configuration error is raised.
    """
    with pytest.raises(state.ConfigurationError):
        state.State.from_charm(config=charm_config)


@pytest.mark.parametrize(
    "charm_config",
    [
        (
            {
                "admin_email": "sample@email.com",
                "mode": "sv",
                "selector": "mail",
            }
        ),
        (
            {
                "admin_email": "sample@email.com",
                "mode": "v",
                "selector": "mail",
            }
        ),
        (
            {
                "admin_email": "sample@email.com",
                "mode": "s",
                "selector": "mail",
            }
        ),
    ],
)
def signing_enabled(charm_config):
    """
    arrange: instantiate the state".
    act: do nothing.
    assert: if the signing enabled property matches the mode.
    """
    charm_state = state.State.from_charm(config=charm_config)

    assert charm_state.signing_enabled == "s" in charm_config["mode"]
