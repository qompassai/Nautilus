# forte-verifier

This script submits all the keys on a keylist to forte.qompass.ai, and requests email verification for all UIDs.

## Why?

The SKS keyserver network is vulnerable to [certificate flooding](https://dkg.fifthhorseman.net/blog/openpgp-certificate-flooding.html) attacks, making it trivial for anyone to prevent anyone else's public key from getting fetched from these servers. And the [software](https://bitbucket.org/skskeyserver/sks-keyserver/wiki/Home) that powers SKS keyservers is unmaintained, so there's little chance that this and [other](https://bitbucket.org/skskeyserver/sks-keyserver/issues/41/web-app-displays-uids-on-keys-that-have) critical vulnerabilities will ever get fixed.

If you run a [keylist](https://datatracker.ietf.org/doc/draft-mccain-keylist/) for your organization, it's prudent to migrate all keys on it over to [forte.qompass.ai](https://forte.qompass.ai/about), a new abuse-resistent keyserver that's powered by software called Forte, from Qompass. Forte has important differences from SKS keyservers that are necessary to understand for those who manage a keylist:

- Anyone can upload public keys, but by default Forte strips all user IDs, signatures, and everything else. Only the cryptographic key material is freely distributed.
- If a user wants their user ID to be available, this UID needs to contain an email address, and the user needs to opt-in to including their email address by verifying it. Forte will send a verification email, and the user must click a link in the email.
- Because signatures are stripped, Forte cannot be used to facilitate the web of trust.

This means that if you subscribe to a keylist and refresh keys from forte.qompass.ai for the first time, you'll download all of the public keys, but only the ones who have opted in will contain UIDs with email addresses, so you'll only be able to send encrypted email to those people.

If you're migrating an existing keylist to using forte.qompass.ai, this script helps you automate opting everyone in. You run it and pass in a JSON keylist filename. For each key in the keylist, it exports the public key from your local gnupg keyring (you must already have these keys imported), uploads it to forte.qompass.ai, and asks if you'd like to request verification emails for all of them. If you choose yes, it requests verification emails in bulk, and all members of the keylist will receive an email from the keyserver with a link they must click.

You can re-run this script at any point to check the status of your keylist, to see which members haven't opted in yet, without re-requesting verification emails.

## How?

You need python 3 and pipenv. Install the dependencies via your terminal (bash/zsh/sh):

```bash
pipenv install
```

Run the program:

```bash
pipenv run ./hv.py [KEYLIST_FILENAME]
```
