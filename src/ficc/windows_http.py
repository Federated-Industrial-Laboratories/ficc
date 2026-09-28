# SPDX-License-Identifier: Apache-2.0
"""Apply fixed HTTPS peer checks and byte limits to the pinned PSRP HTTP client."""

import hashlib
import hmac
import ssl

import requests
from requests.adapters import HTTPAdapter
from urllib3 import PoolManager
from urllib3.connection import HTTPSConnection
from urllib3.connectionpool import HTTPSConnectionPool

MAX_RESPONSE = 2 * 1024 * 1024


def session(transport, ca_pem, fingerprint):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_verify_locations(cadata=ca_pem)

    class Connection(HTTPSConnection):
        def connect(self):
            super().connect()
            if not isinstance(self.sock, ssl.SSLSocket):
                self.close()
                raise ssl.SSLError('The Windows endpoint requires a TLS socket.')
            certificate = self.sock.getpeercert(binary_form=True)
            if not certificate:
                self.close()
                raise ssl.SSLError('The Windows endpoint certificate is absent.')
            actual = hashlib.sha256(certificate).hexdigest()
            if not hmac.compare_digest(actual, fingerprint):
                self.close()
                raise ssl.SSLError('The Windows certificate fingerprint differs.')

    class Pool(HTTPSConnectionPool):
        ConnectionCls = Connection

    class Adapter(HTTPAdapter):
        def init_poolmanager(self, connections, maxsize, block=False, **kwargs):
            self.poolmanager = PoolManager(num_pools=1, maxsize=1, block=True, ssl_context=context)
            self.poolmanager.pool_classes_by_scheme = {'https': Pool}

        def build_connection_pool_key_attributes(self, request, verify, cert=None):
            host, _ = super().build_connection_pool_key_attributes(request, True, None)
            return host, {'ssl_context': context, 'cert_reqs': 'CERT_REQUIRED'}

        def cert_verify(self, conn, url, verify, cert):
            conn.cert_reqs = 'CERT_REQUIRED'
            conn.ca_certs = None
            conn.ca_cert_dir = None

        def proxy_manager_for(self, proxy, **kwargs):
            raise ValueError('Windows transport proxies are not permitted.')

        def send(self, request, stream=False, timeout=None, verify=True, cert=None, proxies=None):
            if request.url != transport.endpoint or request.method != 'POST':
                raise ValueError('The Windows request endpoint differs.')
            response = super().send(request, stream=True, timeout=timeout, verify=True, cert=None, proxies={})
            if 300 <= response.status_code < 400:
                response.close()
                raise ValueError('Windows endpoint redirects are not permitted.')
            if response.headers.get('Content-Encoding', 'identity').lower() != 'identity':
                response.close()
                raise ValueError('Compressed Windows responses are not permitted.')
            # Keep the raw socket available for the library's channel binding check.
            original = response.raw.stream
            def bounded(*args, **kwargs):
                total = 0
                for block in original(*args, **kwargs):
                    total += len(block)
                    if total > MAX_RESPONSE:
                        response.close()
                        raise ValueError('The Windows HTTP response exceeds its byte bound.')
                    yield block
            response.raw.stream = bounded
            return response

    value = requests.Session()
    value.trust_env = False
    value.proxies = {}
    value.headers.update({'Accept-Encoding': 'identity', 'User-Agent': 'FICC Windows transport'})
    value.adapters.clear()
    value.mount('https://', Adapter(max_retries=0))
    transport._build_auth_ntlm(value)
    return value
