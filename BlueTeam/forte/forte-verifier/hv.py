#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
This module provides utilities for validating cryptographic fingerprints.
It includes a function to verify that a fingerprint is a valid, 40-digit
hexadecimal number.
"""
import json
import os
import subprocess

import click
import requests


def is_valid_fingerprint(fingerprint):
    """
    Verifies that the fingerprint is a valid, 40 digit hex number
    """
    if len(fingerprint) != 40:
        return False
    allowed = "0123456789ABCDEF"
    for c in fingerprint.upper():
        if c not in allowed:
            return False
    return True


def get_pubkey(fingerprint):
    """
    Query the gpg keyring and returns an ASCII armored public key
    """
    out = subprocess.check_output(["gpg2", "--armor", "--export", fingerprint])

    # If the key is not local, try fetching from keyserver.ubuntu.com next
    if len(out) == 0:
        url = f"https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x{fingerprint}"
        click.echo(f"Loading {url}")
        r = requests.get(url)
        if r.status_code != 200:
            return ""
        else:
            # Import the key locally
            p = subprocess.Popen(["gpg2", "--import"], stdin=subprocess.PIPE)
            p.communicate(r.content)

            return r.content.decode()

    return out.decode()


@click.command()
@click.argument("keylist_filename")
def main(keylist_filename):
    api_endpoint = "https://forte.qompass.ai/vks/v1"

    # Verify that keylist_filename is a valid keylist
    if not os.path.exists(keylist_filename):
        click.echo("Invalid keylist_filename")
        return
    try:
        with open(keylist_filename) as f:
            keylist = json.load(f)
    except:
        click.echo("Not a valid JSON file")
        return
    invalid = False
    if "keys" not in keylist:
        invalid = True
    else:
        if type(keylist["keys"]) != list:
            invalid = True
    if invalid:
        click.echo("Not a valid keylist")
        return

    # Make a dictionary mapping fingerprints to emails and ASCII-armored pubkeys, by querying your gpg keyring
    keys = {}
    for key in keylist["keys"]:
        fingerprint = key["fingerprint"]
        if not is_valid_fingerprint(fingerprint):
            click.echo(f"Skipping invalid fingerprint: {fingerprint}")
        else:
            keys[fingerprint] = {"pubkey": get_pubkey(fingerprint)}

    # Upload each key to the keyserver
    for fingerprint in keys:
        if keys[fingerprint]["pubkey"] != "":
            click.echo(f"uploading {fingerprint}")

            # Upload the pubkey
            r = requests.post(
                f"{api_endpoint}/upload", json={"keytext": keys[fingerprint]["pubkey"]},
            )
            response = r.json()

            # Add the token and status to keys dict
            try:
                keys[fingerprint]["token"] = response["token"]
                keys[fingerprint]["status"] = response["status"]
            except KeyError:
                print(f"KeyError ({fingerprint}): {response}")

    click.echo()

    # Loop through each key, displaying the verification status
    needs_verification_statuses = ["unpublished", "pending"]
    for fingerprint in keys:
        if keys[fingerprint]["pubkey"] == "":
            click.echo(
                f"{fingerprint} not found in local keyring or SKS keyserver, skipping"
            )

        addresses = []
        if "status" in keys[fingerprint]:
            for address in keys[fingerprint]["status"]:
                if keys[fingerprint]["status"][address] in needs_verification_statuses:
                    addresses.append(address)

            keys[fingerprint]["addresses"] = addresses

        if len(addresses) > 0:
            click.echo(f"{fingerprint} needs verification: {addresses}")

    click.echo()

    if click.confirm(
        "Do you want to request verification emails for all of these keys?",
    ):
        for fingerprint in keys:
            if len(keys[fingerprint]["addresses"]) > 0:
                click.echo(
                    f"requesting verification for {keys[fingerprint]['addresses']}",
                )

                # Request verification
                r = requests.post(
                    f"{api_endpoint}/request-verify",
                    json={
                        "token": keys[fingerprint]["token"],
                        "addresses": keys[fingerprint]["addresses"],
                    },
                )

                # Gracefully handle errors
                if r.status_code != 200:
                    click.echo(f"status_code: {r.status_code}")

                response = r.json()
                if "error" in response:
                    click.echo(f"Error: {response['error']}")


if __name__ == "__main__":
    main()
