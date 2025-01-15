# SMTP DKIM Signing Charm

## Description

The SMTP DKIM Signing Charm installs and configures opendkim.

It's intended to be used together with the [SMTP Relay Charm](https://charmhub.io/smtp-relay).

## Usage

Provision a Juju environment then deploy 2 units with:

```
juju deploy -n2 smtp-dkim-signing
```

Then relate to an already deployed smtp-relay Juju application:

```
juju relate smtp-dkim-signing smtp-relay
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

### Scale Out Usage

To horizontally scale:

```
juju add-unit smtp-dkim-signing
```

---

## Testing

Just run `make unittest`.

---

For more details, [see here](https://charmhub.io/smtp-dkim-signing/configure).
