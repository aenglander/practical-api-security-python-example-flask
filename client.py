import argparse
import hashlib
import json

from datetime import datetime
from uuid import uuid1
from hashlib import sha512

from jwkest.jwe import JWE
from jwkest.jwk import SYMKey
from jwkest.jws import JWS
from requests import Request, Session

parser = argparse.ArgumentParser(description='Make an API request')
parser.add_argument('name', type=str, nargs='?', help='Name to send to the API')
parser.add_argument('-v', '--verbose', help='Verbose output', default=False, dest='verbose', action='store_true')
parser.add_argument('--no-nonce', help='Send no unique nonce with the request', default=False, dest='no_nonce', action='store_true')
parser.add_argument('--no-jwt', help='Send no JWT with the request', default=False, dest='no_jwt', action='store_true')
parser.add_argument('--no-encryption', help='Send the request without encryption', default=False, dest='no_encryption',
                    action='store_true')
parser.add_argument('--key-id', help='Encryption/Signature Key ID', default='key1', dest='key_id')
parser.add_argument('--key', help='Encryption/Signature Key ID', default='bc926745ef6c8dda6ed2689d08d5793d7525cb81',
                    dest='key')
parser.add_argument('--base-url', help='Base URL for the request', default='http://localhost:5000', dest='base_url')
parser.add_argument('--leeway', help='Number of seconds to allow for time differential', default=1, type=int,
                    dest='leeway')
parser.add_argument('--issuer', help='JWT Issuer', default='valid-client', dest='issuer')
parser.add_argument('--audience', help='JWT Audience', default='api-server', dest='audience')

config = parser.parse_args()
config.no_jwt = True

sig_keys = [SYMKey(use='sig', kid=config.key_id, key=config.key)]
enc_keys = [SYMKey(use='enc', kid=config.key_id, key=config.key)]

issuer = 'valid-client'
audience = 'api-server'


def _get_request_token(method: str, path: str, body: str, jti: str, iss: str, aud: str):
    now = int(datetime.utcnow().timestamp())
    claims = {
        'jti': jti,
        'iat': now,
        'nbf': now,
        'exp': now,
        'iss': iss,
        'aud': aud,
        'request': {
            'method': method,
            'path': path
        }
    }

    if body is not None:
        claims['request']['body_hash_alg'] = 'S512'
        claims['request']['body_hash'] = sha512(body.encode('utf8')).hexdigest()

    if config.verbose:
        print("Request JWT Claims:")
        print(json.dumps(claims, indent=2))
        print()

    jws = JWS(json.dumps(claims), alg="HS256")
    signed_content = jws.sign_compact(keys=sig_keys)
    return signed_content


def _get_request_data():
    if config.name is None:
        method = 'GET'
        body = None
        headers = dict()
        print("=== No Request ===")
    else:
        method = 'POST'
        data = json.dumps({'name': config.name}, indent=2)
        print("Unencrypted Body:")
        print(data)
        print()
        if config.no_encryption:
            body = data
            headers = {'content-type': 'application/json'}
        else:
            jwe = JWE(data, alg='A256KW', enc='A256CBC-HS512', cty='application/json')
            body = jwe.encrypt(enc_keys)
            headers = {'content-type': 'application/jose'}

    path = '/'
    jti = None if config.no_nonce else str(uuid1())
    if config.no_jwt:
        headers['Authorization'] = 'Nonce {}'.format(jti)
    else:
        jwt = _get_request_token(method, path, body, jti, config.issuer, config.audience)
        headers['Authentication'] = 'EX-JWT {}'.format(jwt)

    if config.verbose:
        print(method, path, "HTTP/1.1")
        for key, value in headers.items():
            print("{}: {}".format(key, value))
        if body is not None:
            print("\n" + body)

    return method, config.base_url + path, headers, body, jti


def _verify_response(response):
    if not config.no_jwt and response.status_code < 300:
        now = datetime.utcnow().timestamp()
        jwt_token = response.headers.get('X-JWT')
        if jwt_token is None:
            raise Exception("No response header X-JWT")
        jwt = JWS().verify_compact(jwt_token, sig_keys)
        if config.verbose:
            print("Response JWT Claims:")
            print(json.dumps(jwt, indent=2))
            print()
        if jwt['jti'] != jti:
            raise Exception("Unexpected response jti. Expected {} but received {}".format(jti, jwt['jti']))
        if jwt['iss'] != config.audience:
            raise Exception("Unexpected response issuer. Expected {} but received {}".format(audience, jwt['iss']))
        if jwt['aud'] != config.issuer:
            raise Exception("Unexpected response audience. Expected {} but received {}".format(issuer, jwt['aud']))
        if jwt['nbf'] < now - config.leeway:
            raise Exception("Response nbf is out of bounds.")
        if jwt['exp'] > now + config.leeway:
            raise Exception("Response is expired.")
        if jwt['response']['status_code'] != response.status_code:
            raise Exception("Unexpected response stats_code. Expected {} but received {}"
                            .format(response.status_code, jwt['response']['status_code']))
        hashes = dict(S256='sha256', S384='sha384', S512='sha512')
        hasher = hashlib.new(hashes[jwt['response']['body_hash_alg']])
        hasher.update(response.content)
        body_hash = hasher.hexdigest()
        if jwt['response']['body_hash'] != body_hash:
            raise Exception("Unexpected response body_hash")


print("REQUEST:")
print()
method, url, headers, body, jti = _get_request_data()
request = Request(method, url, headers, None, body)
prepared = request.prepare()

response = Session().send(prepared)
print()
print("RESPONSE:")
print()
if config.verbose:
    print(u"HTTP/1.1 {} {}".format(response.status_code, response.reason))
    for header in response.headers.items():
        print(u'{}: {}'.format(*header))
    print(u'\n{}\n'.format(response.content.decode()))

_verify_response(response)

if response.headers.get('content-type') == 'application/jose':
    jwe = JWE()
    decrypted = jwe.decrypt(response.content, enc_keys)
    decoded = decrypted.decode()
    print("Decrypted Body:")
    print(decoded)
elif not config.verbose:
    print(response.text)
