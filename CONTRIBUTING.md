# How to contribute

## Overview

This document explains the processes and practices recommended for contributing enhancements to the SMTP DKIM Signing operator.

- Generally, before developing enhancements to this charm, you should consider [opening an issue
  ](https://github.com/canonical/smtp-dkim-signing-operator/issues) explaining your use case.
- If you would like to chat with us about your use-cases or proposed implementation, you can reach
  us at [Canonical Matrix public channel](https://matrix.to/#/#charmhub-charmdev:ubuntu.com)
  or [Discourse](https://discourse.charmhub.io/).
- Familiarizing yourself with the [Charmed Operator Framework](https://juju.is/docs/sdk) library
  will help you a lot when working on new features or bug fixes.
- All enhancements require review before being merged. Code review typically examines
  - code quality
  - test coverage
  - user experience for Juju operators of this charm.
- Please help us out in ensuring easy to review branches by rebasing your pull request branch onto the `main` branch. This also avoids merge commits and creates a linear Git commit history.

## Developing

The code for this charm can be downloaded as follows:

```
git clone https://github.com/canonical/smtp-dkim-signing-operator
```

You can use the environments created by `tox` for development:

```shell
tox --notest -e unit
source .tox/unit/bin/activate
```

### Testing

* `tox`: Runs all of the basic checks (`lint`, `unit`, `static`, and `coverage-report`).
* `tox -e fmt`: Runs formatting using `black` and `isort`.
* `tox -e lint`: Runs a range of static code analysis to check the code.
* `tox -e static`: Runs other checks such as `bandit` for security issues.
* `tox -e unit`: Runs the unit tests.
* `tox -e integration`: Runs the integration tests.

### Generating src docs for every commit

Run the following command:

```bash
echo -e "tox -e src-docs\ngit add src-docs\n" >> .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

## Build charm

Build the charm in this git repository using:

```shell
charmcraft pack
```

### Deploy

```bash
# Create a model
juju add-model smtp-dkim-signing-dev
# Enable DEBUG logging
juju model-config logging-config="<root>=INFO;unit=DEBUG"
# Deploy the charm (assuming you're on amd64)
juju deploy ./smtp_dkim_signing_ubuntu-24.04-amd64.charm
```

## Canonical contributor agreement

Canonical welcomes contributions to the SMTP DKIM Signing Operator. Please check out our [contributor agreement](https://ubuntu.com/legal/contributors) if you're interested in contributing to the solution.
