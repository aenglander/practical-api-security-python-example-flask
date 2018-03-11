from jwkest.jws import JWS


class TokenSignalHandler:

    def __init__(self, keys) -> None:
        self._keys = keys

    def request_started_handler(self, sender, **extra):
        pass

    def request_finished_handler(self, sender, response, **extra):
        jws = JWS("Lorem ipsum dolor sit amet.", alg="HS256")
        signed_content = jws.sign_compact(keys=self._keys)
        response.headers['X-JWT'] = signed_content


class EncryptionSignalHandler:
    def __init__(self) -> None:
        pass

    def request_started_handler(self, sender, **extra):
        pass

    def request_finished_handler(self, sender, response, **extra):
        pass
