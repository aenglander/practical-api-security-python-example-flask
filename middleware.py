class RootMiddleware(object):

    def __init__(self, app):

        self.app = app

    def __call__(self, environ, start_response):

        def _my_start_response(status, headers):
            _ = self.__start_response(status, headers)
            return _

        self.__start_response = start_response
        x = self.app(environ, _my_start_response)
        return x
