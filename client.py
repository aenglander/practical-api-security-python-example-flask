import argparse
import json
from time import time
from uuid import uuid1
from hashlib import sha512

from jwkest.jwk import SYMKey
from jwkest.jws import JWS
from requests import Request, Session

parser = argparse.ArgumentParser(description='Make an API request')
parser.add_argument('name', type=str, nargs='?', help='Name to send to the API')
parser.add_argument('-v', '--verbose', help='Verbose output', default=False, dest='verbose',
                    action='store_true')

args = parser.parse_args()

sig_keys = [SYMKey(use="sig", kid="key1", key="Super Secret Secret")]


def get_request_token(method: str, path: str, body: str):
    now = int(time())
    claims = {
        'jti': str(uuid1()),
        'iat': now,
        'nbf': now,
        'exp': now,
        'iss': 'valid-aud',
        'aud': 'api-server',
        'request': {
            'method': method,
            'path': path
        }
    }

    if body is not None:
            claims['request']['body_hash_alg'] = 'S512'
            claims['request']['body_hash'] = sha512(body).hexdigest()

    jws = JWS(json.dumps(claims), alg="HS256")
    signed_content = jws.sign_compact(keys=sig_keys)
    return signed_content


method = 'GET' if args.name is None else 'POST'
body = None
path = '/'
request = Request(method, 'http://localhost:5000/')
prepared = request.prepare()
prepared.body = None
jwt_token = get_request_token(prepared.method, path, prepared.body)
prepared.headers['Authentication'] = 'EX-JWT {}'.format(jwt_token)
response = Session().send(prepared)
print(u"HTTP/1.1 {} {}".format(response.status_code, response.reason))
for header in response.headers.items():
    print(u'{}: {}'.format(*header))

print(u'\n{}\n'.format(response.content.decode()))

