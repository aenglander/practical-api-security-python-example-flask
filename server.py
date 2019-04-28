from flask import Flask, request, jsonify, request_started, request_finished
from jwkest.jwk import SYMKey
from cachelib import SimpleCache

from exceptions import HttpException
from signals import OrderedSignalHandler, ReplayPreventionSignalHandler

app = Flask(__name__)


cache = SimpleCache()
replay_prevention_signal_handler = ReplayPreventionSignalHandler(cache)

signal_handler = OrderedSignalHandler(replay_prevention_signal_handler)

request_started.connect(signal_handler.request_started_handler, app)
request_finished.connect(signal_handler.request_finished_handler, app)

cache = SimpleCache()

replay_prevention_signal_handler = ReplayPreventionSignalHandler(cache)
request_started.connect(replay_prevention_signal_handler.request_started_handler, app)



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
