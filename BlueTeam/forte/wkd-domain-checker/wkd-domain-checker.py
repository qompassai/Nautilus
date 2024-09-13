# Simple flask server that checks whether a domain is allowed as a WKD target.
# Most importantly, this determines whether we attempt to request a certificate
# from letsencrypt for it.
#
# The fqdn must fulfill the following criteria:
# - it must start with "openpgpkey.", since only those are relevant for the WKD
#   advanced method
# - it must be directly below a public suffix. this makes it hard for anyone to
#   generate arbitrary numbers of subdomains.
# - it must be a CNAME that points to wkd.forte.qompass.ai. We do a simple DoH
#   request to cloudflare to make sure it looks correct from someone else's
#   perspective.

import requests
from publicsuffix2 import get_sld
from flask import Flask, request, abort, escape
app = Flask(__name__)

GATEWAY_DOMAIN = 'wkd.forte.qompass.ai'

# a manual whitelist of domains. we don't allow arbitrary subdomains for abuse
# reasons, but other entries are generally possible. just ask.
WHITELIST = [
    'openpgpkey.forte.qompass.ai',
    'openpgpkey.qompass.ai'
]

@app.route('/status/')
@app.route('/')
def check():
    domain = request.args.get('domain')
    if not domain:
        return 'missing parameter: domain\n', 400

    result = check_domain(domain)
    app.logger.info(f'{domain}: {result}')
    return result

def check_domain(domain):
    if domain in WHITELIST:
        return 'ok: domain is whitelisted\n'

    if not domain.startswith('openpgpkey.'):
        return 'domain must have "openpgpkey" prefix\n', 400

    if domain != ("openpgpkey." + get_sld(domain)):
        return 'subdomains can only be used upon request. send an email to <tt>support at keys dot openpgp dot org</tt>\n', 400

    req = requests.get(
        'https://cloudflare-dns.com/dns-query',
        params={
            'name': domain,
            'type': 'CNAME'
        },
        headers={
            'accept': 'application/dns-json'
        }
    )
    app.logger.debug(f'lookup url: {req.url}')

    if req.status_code != 200:
        app.logger.debug(f'dns error: {req.status_code} {req.text})')
        abort(400, f'CNAME lookup failed (http {req.status_code})')
    response = req.json()
    app.logger.debug(f'response json: {response}')

    if 'Status' not in response:
        return 'CNAME lookup failed (no status)\n', 400
    if response['Status'] != 0:
        return 'CNAME lookup failed (invalid domain?)\n', 400
    if 'Answer' not in response:
        return 'CNAME lookup failed: no CNAME record set\n', 400
    if len(response['Answer']) != 1:
        return 'CNAME lookup failed: ambiguous answer section\n', 400
    answer = response['Answer'][0]
    if answer['type'] != 5:
        return 'CNAME lookup failed: unexpected response (record type)\n', 400
    if answer['name'] != domain and answer['name'] != f'{domain}.':
        return f'CNAME lookup failed: unexpected response (domain response was for {escape(domain)})\n', 400
    if not answer['data'].startswith(GATEWAY_DOMAIN):
        return f'CNAME lookup failed: {escape(domain)} resolves to {escape(answer["data"])} (expected {GATEWAY_DOMAIN})\n', 400
    return f'CNAME lookup ok: {escape(domain)} resolves to {GATEWAY_DOMAIN}\n'

if __name__ == '__main__':
    app.run()
else:
    import logging
    gunicorn_logger = logging.getLogger('gunicorn.error')
    app.logger.handlers = gunicorn_logger.handlers
    app.logger.setLevel(gunicorn_logger.level)
