from flask import Flask, request, json, make_response, jsonify, request_started, request_finished
from Cryptodome.Cipher import AES
from jwkest.jwk import SYMKey
from jwkest.jws import JWS

from signals import EncryptionSignalHandler, TokenSignalHandler

app = Flask(__name__)


jwk = SYMKey(use="sig", kid="key1", key="Super Secret Secret")


token_signal_handler = TokenSignalHandler([jwk])
request_started.connect(token_signal_handler.request_started_handler, app)
request_finished.connect(token_signal_handler.request_finished_handler, app)

encryption_signal_handler = EncryptionSignalHandler()
request_started.connect(encryption_signal_handler.request_started_handler, app)
request_finished.connect(encryption_signal_handler.request_finished_handler, app)


class HttpException(Exception):

    def __init__(self, message, code=500) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@app.errorhandler(HttpException)
def error_handler(exception: HttpException):
    return jsonify({'error': exception.message}), exception.code


@app.route('/', methods=('GET', 'POST'))
def root():
    if request.method == 'POST':
        try:
            name = request.json['name']
        except (TypeError, KeyError):
            raise HttpException("Invalid request. Must be JSON object with a name attribute!", 400)
    else:
        name = 'World!'

    return jsonify({'Hello': name}), 200


if __name__ == '__main__':
    app.run()
