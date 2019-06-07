import hashlib
import re
from _sha512 import sha512
from datetime import datetime
from io import StringIO
from json import dumps
from typing import List, Tuple, Dict

from cachelib import BaseCache
from jwkest import JWKESTException
from jwkest.jwe import JWE
from jwkest.jwk import Key
from jwkest.jws import JWS
from werkzeug.wsgi import get_input_stream as get_input_stream


def return_error(status_code: int, status_message: str, error_message: str,
                 start_response: callable):
    start_response(f"{status_code} {status_message}", [("content-type", "application/json"),
                                                       ("content-encoding", "UTF-8")])
    return [f"{{\"error\":\"{error_message}\"}}".encode('utf-8')]


def get_code_from_status(status: str) -> int:
    return int(status.split(" ")[0])


def get_header(name: str, headers: List[Tuple[str, str]], default: str = None) -> str:
    for header in headers:
        if header[0].lower() == name.lower():
            return header[1]
    return default


def replace_header(name: str, value: str, headers: List[Tuple[str, str]]):
    for header in headers:
        if header[0].lower() == name.lower():
            headers.remove(header)
    headers.append((name, value))


def get_request(environ: Dict[str, str]) -> str:
    if environ.get('request_data', None) is None:
        environ['request_data'] = get_input_stream(environ).read()
    return environ['request_data']


def read_response(response):
    data = u""
    for chunk in response:
        if isinstance(chunk, bytes):
            chunk = chunk.decode('utf-8')
        data = data + chunk
    return data


class RateLimitingMiddleware:
    def __init__(self, app: callable, cache: BaseCache, rate_count: int, rate_seconds: int) -> None:
        self.__cache = cache
        self.__rate_count = rate_count
        self.__rate_seconds = rate_seconds
        self.__app = app

    def __call__(self, environ: Dict[str, str], start_response: callable):

        time_chunk = int(datetime.utcnow().timestamp()) // self.__rate_seconds
        cache_key = "{}-{}-{}".format(environ['PATH_INFO'], environ['REQUEST_METHOD'], time_chunk)

        if self.__cache.inc(cache_key) > self.__rate_count:
            return return_error(429, "Too many requests!", "Too many requests!", start_response)

        return self.__app(environ, start_response)


class ReplayPreventionMiddleware:
    def __init__(self, app: callable, cache: BaseCache) -> None:
        self.__app = app
        self.__cache = cache

    def __call__(self, environ: Dict[str, str], start_response: callable):
        token = environ.get('HTTP_AUTHORIZATION', None)

        if token is None:
            return return_error(401, "Authorization Required!", "Authorization Required!",
                                start_response)

        if not self.__cache.add(sha512(token.encode('utf-8')).digest(), 1):
            return return_error(400, "Invalid Request!", "Replay Detected", start_response)

        return self.__app(environ, start_response)


class EncryptionMiddleware:
    def __init__(self, app: callable, keys: List[Key]) -> None:
        self.__app = app
        self.__keys = keys

    def __call__(self, environ: Dict, start_response: callable):
        if environ.get('CONTENT_TYPE', '').lower() == u'application/jose':
            jwe = JWE()
            encrypted_body = get_request(environ)
            decrypted_body = jwe.decrypt(encrypted_body, self.__keys)
            environ['wsgi.input'] = StringIO(decrypted_body.decode('utf-8'))
            environ['CONTENT_TYPE'] = u'application/json'
            environ['CONTENT_LENGTH'] = len(decrypted_body)

        delayed_response = DelayedResponse()

        response = self.__app(environ, delayed_response)
        status_code = get_code_from_status(delayed_response.status)
        content_type = get_header("content-type", delayed_response.response_headers)
        if 200 >= status_code < 300 and content_type == 'application/json':
            replace_header("content-type",  'application/jose', delayed_response.response_headers)
            replace_header("content-encoding",  'UTF-8', delayed_response.response_headers)
            data = read_response(response)
            jwe = JWE(data, alg='A256KW', enc='A256CBC-HS512', cty='application/json')
            encrypted_response = jwe.encrypt(self.__keys, kid=self.__keys[0].kid).encode('utf-8')
            replace_header("content-length", str(len(encrypted_response)), delayed_response.response_headers)
            response = [encrypted_response]

        start_response(delayed_response.status, delayed_response.response_headers,
                       delayed_response.exc_info)

        return response


class TokenMiddleware:
    def __init__(self, app: callable, keys: List[Key], leeway: int, cache: BaseCache) -> None:
        self.__app = app
        self.__keys = keys
        self.__leeway = leeway
        self.__cache = cache
        self.__request_jwt_claims = dict(iss='public', aud='example-app')
        self.__hash_algs = dict(S256='sha256', S384='sha384', S512='sha512')

    def __call__(self, environ: Dict[str, str], start_response: callable):
        header = environ.get('HTTP_AUTHORIZATION', u'')
        regex = re.compile(u"^EX-JWT (?P<token>.*)$")
        matches = regex.match(header)
        if matches is None:
            token = None
        else:
            token = matches.groupdict({u'token': None}).get(u'token')

        if not token:
            return_error(401, "Authorization Required", "No EX-JWT authorization token provided",
                         start_response)

        errors = list()
        try:
            request_jwt_claims = JWS().verify_compact(token, self.__keys)

            now = int(datetime.utcnow().timestamp())
            if request_jwt_claims.get('iss') != "valid-client":
                errors.append("missing or invalid issuer")
            if request_jwt_claims.get('aud') != "api-server":
                errors.append("missing or invalid audience")
            if not 'jti' in request_jwt_claims:
                errors.append("missing token ID")
            elif not self.__cache.add(request_jwt_claims['jti'], 1, 3600):
                errors.append("duplicate token ID")
            if 'nbf' not in request_jwt_claims:
                errors.append("missing not before")
            elif not isinstance(request_jwt_claims['nbf'], int):
                errors.append("invalid not before type")
            elif request_jwt_claims['nbf'] + self.__leeway < now:
                errors.append("invalid not before")
            if 'exp' not in request_jwt_claims:
                errors.append("missing expires")
            elif not isinstance(request_jwt_claims['exp'], int):
                errors.append("invalid expires type")
            elif request_jwt_claims['exp'] - self.__leeway > now:
                errors.append("invalid expires")

            if 'request' not in request_jwt_claims:
                errors.append("request claim missing")

            if 'path' not in request_jwt_claims['request']:
                errors.append("request[path] claim missing")
            elif request_jwt_claims['request']['path'] != environ.get('PATH_INFO'):
                errors.append("invalid request[path] claim")

            if 'method' not in request_jwt_claims['request']:
                errors.append("request[method] claim missing")
            elif request_jwt_claims['request']['method'] != environ.get('REQUEST_METHOD'):
                errors.append("invalid request[method] claim")

            content_length = int(environ.get('CONTENT_LENGTH', 0))
            if content_length > 0:
                if 'body_hash_alg' not in request_jwt_claims['request']:
                    errors.append("request[body_hash_alg] claim missing")
                elif request_jwt_claims['request']['body_hash_alg'] not in self.__hash_algs:
                    errors.append("request[body_hash_alg] must be one of: {}".format(", ".join(self.__hash_algs.keys())))
                elif 'body_hash' not in request_jwt_claims['request']:
                    errors.append("request[body_hash_alg] claim missing")

                hasher = hashlib.new(self.__hash_algs[request_jwt_claims['request']['body_hash_alg']])
                hasher.update(get_request(environ))
                actual = hasher.hexdigest()
                if actual != request_jwt_claims['request']['body_hash']:
                    errors.append("invalid body hash")
        except JWKESTException:
            return_error(401, "Authorization Required", "Invalid token", start_response)

        if len(errors) > 0:
            return_error(401, "Authorization Required",
                         "Invalid token: {}".format(", ".join(errors)), start_response)

        delayed_response = DelayedResponse()
        response = self.__app(environ, delayed_response)
        status_code = get_code_from_status(delayed_response.status)
        if status_code < 300:
            response_data = read_response(response)
            now = int(datetime.utcnow().timestamp())
            claims = {
                'jti': request_jwt_claims['jti'],
                'iat': now,
                'nbf': now,
                'exp': now,
                'iss': request_jwt_claims['aud'],
                'aud': request_jwt_claims['iss'],
                'response': {
                    'status_code': status_code,
                    'body_hash_alg': 'S512',
                    'body_hash': sha512(response_data.encode('utf-8')).hexdigest()
                }

            }
            jws = JWS(dumps(claims), alg="HS256")
            signed_content = jws.sign_compact(keys=self.__keys)
            delayed_response.response_headers.append(('X-JWT', signed_content))
        start_response(delayed_response.status, delayed_response.response_headers, delayed_response.exc_info)
        return response


class DelayedResponse:

    def __call__(self, status, response_headers, exc_info=None):
        self.__status = status
        self.__response_headers = response_headers
        self.__exc_info = exc_info

    @property
    def status(self):
        return self.__status

    @property
    def response_headers(self):
        return self.__response_headers

    @property
    def exc_info(self):
        return self.__exc_info

