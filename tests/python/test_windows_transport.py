# SPDX-License-Identifier: Apache-2.0
"""Exercise pinned HTTPS transport with real TLS and bounded private helper processes."""

import hashlib
import json
import os
import ssl
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from ficc.windows_runtime import validate

pytestmark = pytest.mark.skipif(os.environ.get('FICC_WINDOWS_TRANSPORT_TESTS') != '1',
    reason='Set FICC_WINDOWS_TRANSPORT_TESTS=1 and FICC_WINDOWS_RUNTIME for actual helper checks')


@pytest.fixture
def tls(tmp_path):
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
        '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost',
        '-keyout', str(tmp_path / 'key'), '-out', str(tmp_path / 'cert')],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    state = {'mode': 'normal', 'requests': 0}
    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'
        def do_POST(self):
            state['requests'] += 1
            self.rfile.read(int(self.headers.get('Content-Length', '0')))
            content = b'{"ok":true}' if state['mode'] != 'large' else b'x' * (2097152 + 1)
            self.send_response(302 if state['mode'] == 'redirect' else 200)
            self.send_header('Content-Length', str(len(content)))
            if state['mode'] == 'redirect':
                self.send_header('Location', 'https://example.invalid/leak')
            if state['mode'] == 'compressed':
                self.send_header('Content-Encoding', 'gzip')
            self.end_headers()
            try:
                self.wfile.write(content)
            except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
                pass
        def log_message(self, *_):
            pass
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(tmp_path / 'cert', tmp_path / 'key')
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    cert = (tmp_path / 'cert').read_text()
    value = {'host': 'localhost', 'port': server.server_port, 'ca': cert,
             'pin': hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert)).hexdigest(), 'count': 1}
    yield value, state
    server.shutdown()
    server.server_close()
    thread.join(timeout=2)


PROGRAM = '''
import json,sys,warnings
from pathlib import Path
sys.path.insert(0,str(Path(sys.executable).resolve().parents[2]/'helper'))
from ficc.windows_http import session
from pypsrp.negotiate import HTTPNegotiateAuth,NoCertificateRetrievedWarning
warnings.simplefilter('error',NoCertificateRetrievedWarning)
v=json.load(sys.stdin)
class Transport:
 endpoint='https://'+v['host']+':'+str(v['port'])+'/wsman'
 def _build_auth_ntlm(self,s):
  def inspect(response,**kwargs):
   assert HTTPNegotiateAuth._get_cbt_data(response).startswith(b'tls-server-end-point:')
  s.hooks['response'].append(inspect)
s=session(Transport(),v['ca'],v['pin'])
try:
 for i in range(v['count']):
  r=s.post(Transport.endpoint,data=b'fixed test body',timeout=2)
  assert r.json()=={'ok':True}
 print('passed',v['count'])
except Exception:
 print('refused')
 sys.exit(2)
finally:
 s.close()
'''


def invoke(value):
    runtime = Path(os.environ['FICC_WINDOWS_RUNTIME'])
    validate(runtime)
    return subprocess.run([runtime / 'python/bin/python3', '-I', '-B', '-c', PROGRAM],
        input=json.dumps(value), text=True, capture_output=True, timeout=15,
        env={'PATH': '/usr/bin:/bin', 'LANG': 'C', 'HTTPS_PROXY': 'http://127.0.0.1:1',
             'REQUESTS_CA_BUNDLE': '/nonexistent', 'SSL_CERT_FILE': '/nonexistent'})


@pytest.mark.parametrize('count', [1, 64])
def test_real_tls_pin_hostname_ca_and_channel_binding(tls, count):
    value, state = tls
    result = invoke({**value, 'count': count})
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == f'passed {count}'
    assert state['requests'] == count


@pytest.mark.parametrize('mode', ['pin', 'hostname', 'trust', 'redirect', 'compressed', 'large'])
def test_real_tls_security_refusals(tls, mode):
    value, state = tls
    if mode == 'pin':
        value['pin'] = '0' * 64
    elif mode == 'hostname':
        value['host'] = '127.0.0.1'
    elif mode == 'trust':
        value['ca'] = ''
    else:
        state['mode'] = mode
    result = invoke(value)
    assert result.returncode != 0
    if mode in {'pin', 'hostname', 'trust'}:
        assert state['requests'] == 0
    else:
        assert state['requests'] == 1


def test_actual_helper_rejects_malformed_input_without_secret_output():
    runtime = Path(os.environ['FICC_WINDOWS_RUNTIME'])
    before = validate(runtime)
    result = subprocess.run([runtime / 'python/bin/python3', '-I', '-B', runtime / 'helper/entry.py'],
        input=b'{"credentials":"private-test-marker"}', capture_output=True, timeout=5,
        env={'PATH': '/usr/bin:/bin', 'LANG': 'C'})
    assert result.returncode == 1
    assert result.stdout == b'' and result.stderr == b'Windows transport request failed.\n'
    assert validate(runtime) == before
