from flask import Flask, request, jsonify, request_started, request_finished
from jwkest.jwk import SYMKey
from cachelib import SimpleCache
from werkzeug.serving import run_simple

from exceptions import HttpException
from middleware import RateLimitingMiddleware, ReplayPreventionMiddleware, EncryptionMiddleware, \
    TokenMiddleware, FlaskImpersonatorMiddleware

flask_app = Flask(__name__)


@flask_app.errorhandler(Exception)
def error_handler(exception: Exception):
    if isinstance(exception, HttpException):
        response = jsonify({'error': exception.message}), exception.code
    else:
        response = jsonify({'error': str(exception)}), 500

    return response


@flask_app.route('/', methods=('GET', 'POST'))
def root():
    if request.method == 'POST':
        try:
            name = request.json['name']
            if not isinstance(name, str) or not 0 < len(name) < 26:
                raise HttpException("Name attribute must be a string between 1 and 25 characters", 400)
        except (TypeError, KeyError):
            raise HttpException("Must be JSON object with a name attribute!", 400)
    else:
        name = 'World!'

    return jsonify(Hello=name), 200


cache = SimpleCache()

encryption_keys = [SYMKey(use="enc", kid="key1", key="bc926745ef6c8dda6ed2689d08d5793d7525cb81")]
signature_keys = [SYMKey(use="sig", kid="key1", key="bc926745ef6c8dda6ed2689d08d5793d7525cb81")]

app = EncryptionMiddleware(flask_app, encryption_keys)
app = TokenMiddleware(app, signature_keys, leeway=1, cache=cache)
app = RateLimitingMiddleware(app, cache, 1, 10)
app = ReplayPreventionMiddleware(app, cache)
app = FlaskImpersonatorMiddleware(app, flask_app)
del flask_app
