import json
import random
import string

from requests import request

from .utils import DLSigner, attr_generator, ClientError


class Method:
    id_chars = string.ascii_letters + string.digits

    def __init__(self, name: str, interface):
        self.name = name
        self.signer = interface.signer
        self.api_key = interface.client.api_key
        self.host = '.'.join((interface.name, interface.client.endpoint))

    def __call__(self, *args, **kwargs):
        if args and kwargs:
            raise AttributeError(
                'You cannot specify named and positional arguments together')

        response = self.request(*args, **kwargs)
        return self.process(response)

    def body(self, *args, **kwargs):
        return json.dumps({
            'jsonrpc': '2.0',
            'id': ''.join(random.sample(self.id_chars, 6)),
            'method': self.name,
            'params': self.prepare_params(args or kwargs)
        }, sort_keys=True).encode('utf-8')

    def prepare_params(self, params):
        if isinstance(params, dict):
            return dict(params, api_key=self.api_key)
        return [self.api_key] + list(params)

    def request(self, *args, **kwargs):
        body = self.body(*args, **kwargs)

        headers = {'Content-Type': 'application/json', 'Host': self.host}
        headers.update(
            self.signer.sign({
                'uri': '/',
                'method': 'POST',
                'headers': headers,
                'body': bytearray(body)
            }),
            Cookie=f'acc_variant={{\"current\":\"{self.host}::PUBLIC\"}}')

        return request(
            'POST', f'https://{self.host}/', data=body, headers=headers)

    @staticmethod
    def process(response):
        if response.status_code == 200:
            data = json.loads(response.content)

            if data.get('error'):
                raise ClientError(**data['error'])

            return data.get('result')

        raise ClientError(
            -32000, f'Conn: Invalid status code {response.status_code}')


@attr_generator(Method)
class Interface:
    def __init__(self, name, client):
        self.name = name
        self.client = client
        self.signer = DLSigner('pulsapi', client.api_key, client.secret_key)


@attr_generator(Interface)
class ContentApiClient:
    def __init__(self, endpoint: str, api_key: str, secret_key: str):
        self.endpoint = endpoint
        self.api_key = api_key
        self.secret_key = secret_key
