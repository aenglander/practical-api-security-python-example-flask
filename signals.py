import hashlib
from datetime import datetime
from time import time
from typing import List
import re
from flask import request, json, Request, Response
from jwkest import JWKESTException
from jwkest.jwe import JWE
from jwkest.jwk import Key
from jwkest.jws import JWS
from hashlib import sha512
from cachelib import BaseCache

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


class ReplayPreventionSignalHandler(SignalHandler):
    def __init__(self, cache: BaseCache) -> None:
        self.__cache = cache

    def request_started_handler(self, sender, **extra):
        token = request.headers.get('Authorization', None)
        if token is None:
            raise HttpException("Authorization Required!", 401)
        if not self.__cache.add(sha512(token.encode('utf-8')).digest(), 1):
            raise HttpException("Invalid Request: Replay Detected", 400)

    def request_finished_handler(self, sender, response: Response, **extra):
        pass
