import datetime
import hashlib
import hmac
from copy import deepcopy
from functools import wraps
from urllib.parse import urlparse, parse_qsl, quote

SCOPE = 'dl1_request'


class DLSigner(object):
    __slots__ = ['service', 'access_key', 'secret_key', 'algorithm', 'solution', 'hash_method']

    def __init__(self, service, access_key, secret_key, algorithm='DL-HMAC-SHA256', solution='RING'):
        """
        Signer initialization, accepts arguments that are constant in
        signing process and not related to specific request
        :param service:
        :param access_key: Key that allows you to access to API
        :param secret_key: Key
        :param algorithm: One of following hashing algorithms:
            * DL-HMAC-SHASHA224,
            * DL-HMAC-SHASHA256, - if algorithm param is missing, used as default value
            * DL-HMAC-SHASHA384,
            * DL-HMAC-SHASHA512
        :param solution: Solution which aggregates a several services.
        """
        assert service, 'Missing service parameter.'
        self.service = service
        assert access_key, 'Missing access_key parameter.'
        self.access_key = access_key
        assert secret_key, 'Missing secret_key parameter'
        self.secret_key = secret_key
        self.solution = solution

        assert algorithm.startswith('DL-HMAC-SHA'), 'Invalid hashing method.'
        self.algorithm = algorithm
        self.hash_method = algorithm.split('-')[-1].lower()
        assert self.hash_method in (
            'sha224', 'sha256', 'sha384', 'sha512'), 'Invalid hashing algorithm.'
        self.hash_method = getattr(hashlib, self.hash_method)

    @staticmethod
    def _check_sign_params(request):
        """Checks params of request dictionary."""
        assert 'headers' in request, 'Missing headers.'
        assert_headers = set(k.lower() for k in request['headers'])
        assert 'host' in assert_headers, 'Missing Host parameter.'
        if 'body' in request:
            assert isinstance(request['body'], bytearray), \
                f'Body must be instance of bytes. not {type(request["body"])}'
        assert 'content-type' in assert_headers
        copied_request = deepcopy(request)
        if 'x-dl-date' not in assert_headers:
            copied_request['headers']['X-DL-Date'] = datetime.datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
        del assert_headers
        return copied_request

    def _sign(self, key, msg, hex_output=False):
        """Performs hashing, returns digest or hexdigest depending on 'hex_output' argument."""
        key = key if isinstance(key, bytes) else key.encode('utf-8')
        msg = msg if isinstance(msg, bytes) else msg.encode('utf-8')
        sign = hmac.new(key, msg, self.hash_method)
        return sign.digest() if not hex_output else sign.hexdigest()

    def _get_canonical_request(self, request):
        """Return formatted string of canonical request data."""
        method = request['method']
        uri = urlparse(request.get('uri', '/'))
        payload = request.get('body', b'')
        headers = self._get_headers(request)

        params = parse_qsl(uri.query, keep_blank_values=True)
        params = '&'.join('{}={}'.format(quote(k, safe='-_.~'), quote(v, safe='-_.~')) for k, v in sorted(params))

        return "{method}\n{uri}\n{params}\n{canonical_headers}\n{signed_headers}\n{payload_hash}".format(
            method=method,
            uri=quote(uri.path, safe='/-_.~'),
            params=params,
            canonical_headers=headers['canonical_headers'],
            signed_headers=headers['signed_headers'],
            payload_hash=self.hash_method(payload).hexdigest()
        )

    @staticmethod
    def _get_headers(request):
        """Method returning dictionary with formatted strings of canonical_headers and signed_headers."""
        canonical_headers = []
        signed_headers = []

        for header_key, header_value in sorted(request['headers'].items(), key=lambda s: s[0].lower()):
            canonical_headers.append('{}:{}'.format(header_key.lower(), header_value.strip()))
            signed_headers.append(header_key.lower())
        canonical_headers = '\n'.join(canonical_headers)
        signed_headers = ';'.join(signed_headers)

        return {'canonical_headers': canonical_headers,
                'signed_headers': signed_headers}

    def _get_string_to_sign(self, canonical_request, date):
        return "{algorithm}\n{date}\n{scope}\n{canonical_request_hash}".format(
            algorithm=self.algorithm,
            date=date,
            scope=date[:8] + '/' + self.solution + '/' + self.service + '/' + SCOPE,
            canonical_request_hash=self.hash_method(canonical_request.encode('utf-8')).hexdigest()
        )

    def _get_signing_key(self, date):
        key = self._sign('DL' + self.secret_key, date[:8])
        key = self._sign(key, self.solution)
        key = self._sign(key, self.service)
        key = self._sign(key, SCOPE)
        return key

    def _get_signature(self, request):
        """Get_signature is calling other methods to process data to finally
            return a signature. """
        canonical_request = self._get_canonical_request(request)
        string_to_sign = self._get_string_to_sign(canonical_request, request['headers']['X-DL-Date'])
        signing_key = self._get_signing_key(request['headers']['X-DL-Date'])
        signature = self._sign(signing_key, string_to_sign, True)
        return signature

    def sign(self, original_request):
        """
        Signs request and returns dictionary with parameters required for authorization process.
            :param original_request: has to be an instance of dict with keys:
                * method: - with values POST/GET/PUT/DELETE
                * uri: URI of the request. If there is no URI given in request dict,
                program will insert default value of URI.
                * headers: - headers of your requests. This key has to be a dictionary.
                    Into headers you have to put 'host' key.
                * payload: - optional.
        :returns: dict:
        """
        request = self._check_sign_params(original_request)
        return {
            'Authorization':
                '{algorithm} Credential={credentials},SignedHeaders={signed_headers},Signature={signature}'.format(
                    algorithm=self.algorithm.upper(),
                    credentials=self.access_key + '/' + request['headers']['X-DL-Date'][:8] +
                                '/' + self.solution + '/'
                                + self.service + '/' + SCOPE,
                    signed_headers=self._get_headers(request)['signed_headers'],
                    signature=self._get_signature(request)
                ),
            'X-DL-Date': request['headers']['X-DL-Date']}


class ClientError(Exception):

    def __init__(self, code, message, data=''):
        self.code = code
        self.message = message
        self.data = data

    def __str__(self):
        return f'code={self.code} message={self.message}' \
            f'{f" data={self.data}" if self.data else ""}'


def attr_generator(cls):
    def getattr(self, item):
        if item.isidentifier() and not item.startswith('_'):
            return cls(item, self)
        raise AttributeError(f'{cls.__name__} must be public method')

    def add_attr(klass):
        klass.__getattr__ = getattr
        return klass

    return add_attr


def convert(func, iterable_type):

    @wraps(func)
    def converted(*args, **kwargs):
        return iterable_type(func(*args, **kwargs))

    return converted
