from time import time
from typing import List
from uuid import uuid1

import re
from flask import request, json, Request
from jwkest.jwe import JWE
from jwkest.jwk import Key
from jwkest.jws import JWS
from hashlib import sha512
from werkzeug.contrib.cache import BaseCache

from exceptions import HttpException


def get_token_from_request(request: Request):
    header = request.headers.get('Authentication', u'')
    regex = re.compile(u"^EX-JWT (?P<token>.*)$")
    matches = regex.match(header)
    if matches is None:
        token = None
    else:
        token = matches.groupdict({u'token': None}).get(u'token')
    return token


class TokenSignalHandler:

    def __init__(self, keys) -> None:
        self._keys = keys

    def request_started_handler(self, sender, **extra):
        request.jwt_claims = {
            'jti': uuid1(),
            'iss': 'public',
            'aud': 'example-app'
        }

    def request_finished_handler(self, sender, response, **extra):
        now = int(time())
        claims = {
            'jti': request.jwt_claims['jti'],
            'iat': now,
            'nbf': now,
            'exp': now,
            'iss': request.jwt_claims['aud'],
            'aud': request.jwt_claims['iss'],
            'response': {
                'status_code': response.status_code,
                'body_hash_alg': 'S512',
                'body_hash': sha512(response.data).hexdigest()
            }

        }
        jws = JWS(json.dumps(claims), alg="HS256")
        signed_content = jws.sign_compact(keys=self._keys)
        response.headers['X-JWT'] = signed_content


class EncryptionSignalHandler:
    def __init__(self, keys: List[Key]) -> None:
        self._keys = keys

    def request_started_handler(self, sender, **extra):
        if request.content_type == u'application/jose':
            jwe = JWE()
            decrypted = jwe.decrypt(request.body, self._keys)

    def request_finished_handler(self, sender, response, **extra):
        if response.content_type == 'application/json':
            jwe = JWE(str(response.data), alg='A256KW', enc='A256CBC-HS512', cty='application/json')
            encrypted = jwe.encrypt(self._keys, kid=self._keys[0].kid)
            response.content_type = 'application/jose'
            response.data = encrypted


class ReplayPreventionSignalHandler:
    def __init__(self, cache: BaseCache) -> None:
        self.__cache = cache

    def request_started_handler(self, sender, **extra):
        token = get_token_from_request(request)
        if token is None:
            raise HttpException("Authorization required", 401)
        if not self.__cache.add(sha512(token.encode('utf-8')), 1):
            raise HttpException("Invalid Request", 400)
