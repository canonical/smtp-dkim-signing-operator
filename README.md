[![CharmHub Badge](https://charmhub.io/smtp-dkim-signing/badge.svg)](https://charmhub.io/smtp-dkim-signing)
[![Publish to edge](https://github.com/canonical/smtp-dkim-signing-operator/actions/workflows/publish_charm.yaml/badge.svg)](https://github.com/canonical/smtp-dkim-signing-operator/actions/workflows/publish_charm.yaml)
[![Promote charm](https://github.com/canonical/smtp-dkim-signing-operator/actions/workflows/promote_charm.yaml/badge.svg)](https://github.com/canonical/smtp-dkim-signing-operator/actions/workflows/promote_charm.yaml)
[![Discourse Status](https://img.shields.io/discourse/status?server=https%3A%2F%2Fdiscourse.charmhub.io&style=flat&label=CharmHub%20Discourse)](https://discourse.charmhub.io)

# SMTP DKIM Signing Operator

A [Juju](https://juju.is/) [charm](https://juju.is/docs/olm/charmed-operators) deploying and managing [OpenDKIM](http://www.opendkim.org/). OpenDKIM is an open source implementation of the DKIM (Domain Keys Identified Mail) sender authentication system proposed by the E-mail Signing Technology Group (ESTG).

This charm intended to be used together with the [SMTP Relay Charm](https://charmhub.io/smtp-relay).

For information about how to deploy, integrate, and manage this charm, see the Official [SMTP DKIM Signing Operator Documentation](https://charmhub.io/smtp-dkim-signing/docs).

## Get started

Provision a Juju environment then deploy 2 units with:

```
juju deploy -n2 smtp-dkim-signing
```

Then integrate to an already deployed smtp-relay Juju application:

```
juju integrate smtp-dkim-signing smtp-relay
```

To horizontally scale:

```
juju add-unit smtp-dkim-signing
```

### Generating new OpenDKIM signing keys

First generate the keys to be used:

```
domain=mydomain.local
selector=$(date '+%Y%m%d')
opendkim-genkey -s $(date '+%Y%m%d') -d ${domain?}
mv ${selector}.private ${domain?}-${selector}.private
mv ${selector}.txt ${domain?}-${selector}.txt
```

Then copy out the keys:

```
units="$(juju status dkim-signing | grep '^dkim-signing/[0-9]*' -o | sort -r)"
for unit in $units; do
    echo "*** ${unit} ***"
    juju run --unit ${unit} "sudo -iu ubuntu mkdir -p ~ubuntu/opendkim-keys; chmod go-rwx ~ubuntu/opendkim-keys"
    juju scp ${domain?}-${selector}.private ${unit}:opendkim-keys/
    juju run --unit ${unit} "mv ~ubuntu/opendkim-keys/*.private /etc/dkimkeys/; chown -R opendkim: /etc/dkimkeys/; chmod -R go-rwx /etc/dkimkeys/"
done
```
TODO: Include config option or action to copy/push these keys out.

Add or publish new keys from ${domain}-${selector}.txt in DNS. Then apply and switch signing to using it:

```
juju config smtp-dkim-signing selector=${selector} keytable="${selector}._domainkey.${domain?} ${domain?}:${selector}:/etc/dkimkeys/${domain?}-${selector}.private" signingtable="*@${domain?} ${selector}._domainkey.${domain?}"
```

## Learn more
* [Read more](https://charmhub.io/smtp-dkim-signing) <!--Link to the charm's official documentation-->
* [Developer documentation](http://www.opendkim.org/docs.html) <!--Link to any developer documentation-->
* [Official webpage](http://www.opendkim.org/) <!--(Optional) Link to official webpage/blog/marketing content-->
* [Troubleshooting](https://matrix.to/#/#charmhub-charmdev:ubuntu.com) <!--(Optional) Link to a page or section about troubleshooting/FAQ-->
## Project and community
* [Issues](https://github.com/canonical/smtp-dkim-signing-operator/issues) <!--Link to GitHub issues (if applicable)-->
* [Contributing](https://charmhub.io/smtp-dkim-signing/docs/how-to-contribute) <!--Link to any contribution guides-->
* [Matrix](https://matrix.to/#/#charmhub-charmdev:ubuntu.com) <!--Link to contact info (if applicable), e.g. Matrix channel-->
