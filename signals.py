import hashlib
from datetime import datetime
from typing import List
import re
from flask import request, json, Request, Response
from jwkest import JWKESTException
from jwkest.jwe import JWE
from jwkest.jwk import Key
from jwkest.jws import JWS
from hashlib import sha512
from werkzeug.contrib.cache import BaseCache

from exceptions import HttpException


class SignalHandler:
    def request_started_handler(self, sender, **extra):
        raise NotImplementedError

    def request_finished_handler(self, sender, response: Response, **extra):
        raise NotImplementedError


class OrderedSignalHandler(SignalHandler):
    """
    This class ensure that signal handlers are executed in order to recreate
    the functionality of middleware. Signal handlers are executed in an
    arbitrary order which is not how we want our handlers to work. This class
    gets around that problem.
    """
    def __init__(self, *signal_handlers: List[SignalHandler]) -> None:
        self.__signal_handlers = signal_handlers

    def request_started_handler(self, sender, **extra):
        for signal_handler in self.__signal_handlers:
            signal_handler.request_started_handler(sender, **extra)

    def request_finished_handler(self, sender, response: Response, **extra):
        for signal_handler in reversed(self.__signal_handlers):
            signal_handler.request_finished_handler(sender, response, **extra)


def get_token_from_request(request: Request):
    header = request.headers.get('Authentication', u'')
    regex = re.compile(u"^EX-JWT (?P<token>.*)$")
    matches = regex.match(header)
    if matches is None:
        token = None
    else:
        token = matches.groupdict({u'token': None}).get(u'token')
    return token


class TokenSignalHandler(SignalHandler):

    def __init__(self, keys: List, leeway: int, cache: BaseCache) -> None:
        self._keys = keys
        self._leeway = leeway
        self._cache = cache
        self._request_jwt_claims = dict(iss='public', aud='example-app')
        self._hash_algs = dict(S256='sha256', S384='sha384', S512='sha512')

    def request_started_handler(self, sender, **extra):
        token = get_token_from_request(request)
        if not token:
            raise HttpException("No EX-JWT authorization token provided", 401)

        try:
            self._request_jwt_claims = JWS().verify_compact(token, self._keys)
        except JWKESTException:
            raise HttpException("Invalid token", 401)

        errors = list()
        now = int(datetime.utcnow().timestamp())
        if self._request_jwt_claims.get('iss') != "valid-client":
            errors.append("missing or invalid issuer")
        if self._request_jwt_claims.get('aud') != "api-server":
            errors.append("missing or invalid audience")
        if not 'jti' in self._request_jwt_claims:
            errors.append("missing token ID")
        elif not self._cache.add(self._request_jwt_claims['jti'], 1, 3600):
            errors.append("duplicate token ID")
        if 'nbf' not in self._request_jwt_claims:
            errors.append("missing not before")
        elif not isinstance(self._request_jwt_claims['nbf'], int):
            errors.append("invalid not before type")
        elif self._request_jwt_claims['nbf'] + self._leeway < now:
            errors.append("invalid not before")
        if 'exp' not in self._request_jwt_claims:
            errors.append("missing expires")
        elif not isinstance(self._request_jwt_claims['exp'], int):
            errors.append("invalid expires type")
        elif self._request_jwt_claims['exp'] - self._leeway > now:
            errors.append("invalid expires")

        if 'request' not in self._request_jwt_claims:
            errors.append("request claim missing")

        if 'path' not in self._request_jwt_claims['request']:
            errors.append("request[path] claim missing")
        elif self._request_jwt_claims['request']['path'] != request.path:
            errors.append("invalid request[path] claim")

        if 'method' not in self._request_jwt_claims['request']:
            errors.append("request[method] claim missing")
        elif self._request_jwt_claims['request']['method'] != request.method:
            errors.append("invalid request[method] claim")

        if request.content_length is not None and request.content_length > 0:
            if 'body_hash_alg' not in self._request_jwt_claims['request']:
                errors.append("request[body_hash_alg] claim missing")
            elif self._request_jwt_claims['request']['body_hash_alg'] not in self._hash_algs:
                errors.append("request[body_hash_alg] must be one of: {}".format(", ".join(self._hash_algs.keys())))
            elif 'body_hash' not in self._request_jwt_claims['request']:
                errors.append("request[body_hash_alg] claim missing")

            hasher = hashlib.new(self._hash_algs[self._request_jwt_claims['request']['body_hash_alg']])
            hasher.update(request.data)
            actual = hasher.hexdigest()
            if actual != self._request_jwt_claims['request']['body_hash']:
                errors.append("invalid body hash")

        if len(errors) > 0:
            raise HttpException("Invalid token: {}".format(", ".join(errors)), 401)

    def request_finished_handler(self, sender, response, **extra):
        if response.status_code < 300:
            now = int(datetime.utcnow().timestamp())
            claims = {
                'jti': self._request_jwt_claims['jti'],
                'iat': now,
                'nbf': now,
                'exp': now,
                'iss': self._request_jwt_claims['aud'],
                'aud': self._request_jwt_claims['iss'],
                'response': {
                    'status_code': response.status_code,
                    'body_hash_alg': 'S512',
                    'body_hash': sha512(response.data).hexdigest()
                }

            }
            jws = JWS(json.dumps(claims), alg="HS256")
            signed_content = jws.sign_compact(keys=self._keys)
            response.headers['X-JWT'] = signed_content


class EncryptionSignalHandler(SignalHandler):
    def __init__(self, keys: List[Key]) -> None:
        self._keys = keys

    def request_started_handler(self, sender, **extra):
        if request.content_type == u'application/jose':
            jwe = JWE()
            decrypted = jwe.decrypt(request.get_data(), self._keys)
            request._cached_data = decrypted
            cached_json = json.loads(decrypted)
            request._cached_json = (cached_json, cached_json)

    def request_finished_handler(self, sender, response: Response, **extra):
        if 200 <= response.status_code < 300 and response.content_type == 'application/json':
            data = response.get_data(as_text=True)
            jwe = JWE(data, alg='A256KW', enc='A256CBC-HS512', cty='application/json')
            encrypted = jwe.encrypt(self._keys, kid=self._keys[0].kid)
            response.content_type = 'application/jose'
            response.data = encrypted


class ReplayPreventionSignalHandler(SignalHandler):
    def __init__(self, cache: BaseCache) -> None:
        self.__cache = cache

    def request_started_handler(self, sender, **extra):
        token = get_token_from_request(request)
        if token is None:
            raise HttpException("Authorization Required!", 401)
        if not self.__cache.add(sha512(token.encode('utf-8')), 1):
            raise HttpException("Invalid Request: Replay Detected", 400)

    def request_finished_handler(self, sender, response: Response, **extra):
        pass


class RateLimitingSignalHandler(SignalHandler):
    def __init__(self, cache: BaseCache, rate_count: int, rate_seconds: int) -> None:
        self.__cache = cache
        self.__rate_count = rate_count
        self.__rate_seconds = rate_seconds

    def request_started_handler(self, sender, **extra):
        def _get_cache_key():
            time_chunk = int(datetime.utcnow().timestamp()) // self.__rate_seconds
            key = "{}-{}-{}".format(request.path, request.method, time_chunk)
            return key

        cache_key = _get_cache_key()
        if self.__cache.inc(cache_key) > self.__rate_count:
            raise HttpException("Rate limit exceeded", 429)

    def request_finished_handler(self, sender, response: Response, **extra):
        pass
