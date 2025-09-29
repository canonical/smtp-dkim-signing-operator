# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Charm state."""

import itertools
import logging
import re
from typing import Any

from pydantic import (
    BaseModel,
    EmailStr,
    Field,
    ValidationError,
    ValidationInfo,
    field_validator,
)

logger = logging.getLogger(__name__)


# RFC-1034 and RFC-2181 compliance REGEX for validating FQDNs
HOSTNAME_REGEX = (
    r"(?=.{1,253})(?!.*--.*)(?:(?!-)(?![0-9])[a-zA-Z0-9-]"
    r"{1,63}(?<!-)\.){1,}(?:(?!-)[a-zA-Z0-9-]{1,63}(?<!-))"
)
MODE_REGEX = r"^(s|v|sv|vs)$"


class CharmStateBaseError(Exception):
    """Represents an error with charm state."""


class ConfigurationError(CharmStateBaseError):
    """Exception raised when a charm configuration is found to be invalid.

    Attributes:
        msg: Explanation of the error.
    """

    def __init__(self, msg: str):
        """Initialize a new instance of the ConfigurationError exception.

        Args:
            msg: Explanation of the error.
        """
        self.msg = msg


def _parse_list(raw_list: str | None) -> list[str]:
    """Parse list input.

    Args:
        raw_list: the list map content.

    Returns:
        a list of strings.
    """
    return raw_list.split(",") if raw_list else []


class State(BaseModel):  # pylint: disable=too-few-public-methods,too-many-instance-attributes
    """The SMTP DKIM operator charm state.

    Attributes:
        admin_email: Administrator's email address where root@ emails will go to.
        domains: List of domains to sign messages for.
        keytable: Map that associates selectors to domains.
        mode: Operating mode.
        selector: Selector to use when signing messages with DKIM.
        signing_enabled: if the charm behaves like a signer.
        signing_key: the signing key.
        signingtable: Map that associates private keys to domains.
        trusted_sources: List of networks or hosts trusted to sign messages.
    """

    admin_email: EmailStr | None
    domains: list[str]
    keytable: str | None
    signing_key: str | None
    signingtable: str | None
    trusted_sources: list[str]
    mode: str = Field(pattern=MODE_REGEX)
    selector: str = Field(min_length=1)

    @field_validator("domains")
    @classmethod
    def validate_domains(cls, domains: list[str], _: ValidationInfo) -> list[str]:
        """Validate the domains field..

        Args:
            domains: the list of domains to validate.

        Returns:
            the list of valid domains.

        Raises:
            ValueError: if invalid state values are found.
        """
        if invalid_domains := [
            domain for domain in domains if not re.match(HOSTNAME_REGEX, domain)
        ]:
            raise ValueError(f"Domains {invalid_domains} contain invalid characters")
        return domains

    @property
    def signing_enabled(self) -> bool:
        """If the charm behaves as signer."""
        return "s" in self.mode

    @classmethod
    def from_charm(cls, config: dict[str, Any]) -> "State":
        """Initialize the state from charm.

        Args:
            config: the charm configuration.

        Returns:
            Current charm state.

        Raises:
            ConfigurationError: if invalid state values were encountered.
        """
        try:
            domains = _parse_list(config.get("domains"))
            trusted_sources = _parse_list(config.get("trusted_sources"))

            return cls(
                admin_email=config.get("admin_email"),
                domains=domains,
                keytable=config.get("keytable"),
                mode=config.get("mode", ""),
                selector=config.get("selector", ""),
                signing_key=config.get("signing_key"),
                signingtable=config.get("signingtable"),
                trusted_sources=trusted_sources if trusted_sources else ["0.0.0.0/0"],
            )

        except ValueError as exc:
            raise ConfigurationError("Invalid configuration") from exc
        except ValidationError as exc:
            error_fields = set(
                itertools.chain.from_iterable(error["loc"] for error in exc.errors())
            )
            error_field_str = " ".join(f"{f}" for f in error_fields)
            raise ConfigurationError(f"Invalid configuration: {error_field_str}") from exc
