from flask import Flask, request, jsonify, request_started, request_finished
from jwkest.jwk import SYMKey
from werkzeug.contrib.cache import SimpleCache

from exceptions import HttpException
from signals import EncryptionSignalHandler, TokenSignalHandler, ReplayPreventionSignalHandler, \
    RateLimitingSignalHandler

app = Flask(__name__)

cache = SimpleCache()

replay_prevention_signal_handler = ReplayPreventionSignalHandler(cache)
rate_limiting_signal_handler = RateLimitingSignalHandler(cache, 1, 10)
token_signal_handler = TokenSignalHandler(
    [SYMKey(use="sig", kid="key1", key="bc926745ef6c8dda6ed2689d08d5793d7525cb81")], leeway=1, cache=cache)
encryption_signal_handler = EncryptionSignalHandler(
    [SYMKey(use="enc", kid="key1", key="bc926745ef6c8dda6ed2689d08d5793d7525cb81")])

request_started.connect(encryption_signal_handler.request_started_handler, app)
request_started.connect(token_signal_handler.request_started_handler, app)
request_started.connect(rate_limiting_signal_handler.request_started_handler, app)
request_started.connect(replay_prevention_signal_handler.request_started_handler, app)

request_finished.connect(token_signal_handler.request_finished_handler, app)
request_finished.connect(encryption_signal_handler.request_finished_handler, app)


@app.errorhandler(Exception)
def error_handler(exception: Exception):
    if isinstance(exception, HttpException):
        response = jsonify({'error': exception.message}), exception.code
    else:
        response = jsonify({'error': str(exception)}), 500

    return response


@app.route('/', methods=('GET', 'POST'))
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


if __name__ == '__main__':
    app.run()
