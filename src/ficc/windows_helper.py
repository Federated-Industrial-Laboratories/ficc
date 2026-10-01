# SPDX-License-Identifier: Apache-2.0
"""Send fixed command names and literal parameters through a registered JEA endpoint."""

import logging
import resource
import sys
import warnings

from . import module_windows_spec as spec
from .module_windows_private import credentials, trust


class IdentityChanged(ValueError):
    """Refuse commands when the authenticated endpoint has a different identity."""


def execute(value):
    from pypsrp.negotiate import NoCertificateRetrievedWarning  # type: ignore[import-not-found]
    from pypsrp.powershell import PowerShell, RunspacePool  # type: ignore[import-not-found]
    from pypsrp.wsman import WSMan  # type: ignore[import-not-found]

    from .windows_http import session
    warnings.simplefilter('error', NoCertificateRetrievedWarning)
    spec.fields(value, {'version', 'host', 'port', 'configuration', 'certificate_sha256',
                        'ca_pem', 'credentials', 'commands'}, {'expected_machine_identity'})
    if value['version'] != 1:
        raise ValueError('The Windows protocol version differs.')
    spec.host(value['host'])
    spec.integer(value['port'], 1, 65535)
    spec.text(value['configuration'], 64)
    spec.identity(value['certificate_sha256'], 64)
    account = credentials(value['credentials'])
    trust(value['ca_pem'])
    commands = value['commands']
    expected = value.get('expected_machine_identity')
    if 'expected_machine_identity' in value:
        spec.identity(expected, 64)
    if not isinstance(commands, list) or not 1 <= len(commands) <= 64:
        raise ValueError('Invalid Windows command count.')
    username = (account['domain'] + '\\' if account['domain'] else '') + account['username']
    client = WSMan(value['host'], port=value['port'], ssl=True, auth='ntlm', username=username,
                   password=account['password'], cert_validation=True, no_proxy=True,
                   connection_timeout=5, read_timeout=8, operation_timeout=5,
                   reconnection_retries=0, negotiate_send_cbt=True)
    client.transport.session = session(client.transport, value['ca_pem'], value['certificate_sha256'])
    results = []
    try:
        with RunspacePool(client, configuration_name=value['configuration'], min_runspaces=1, max_runspaces=1) as pool:
            def invoke(command):
                spec.fields(command, {'command', 'parameters'})
                shell = PowerShell(pool)
                shell.add_cmdlet(command['command'])
                for key, item in command['parameters'].items():
                    shell.add_parameter(key, item)
                output = shell.invoke()
                if shell.had_errors or len(output) != 1 or not isinstance(output[0], str):
                    raise ValueError('The Windows command did not return one JSON result.')
                return spec.decode(output[0].encode('utf-8'))
            if expected is not None:
                actual = invoke({'command': 'Get-FICCEndpointIdentity', 'parameters': {}})
                spec.fields(actual, {'machine_identity'})
                if spec.identity(actual['machine_identity'], 64) != expected:
                    raise IdentityChanged('The Windows machine identity changed.')
            for command in commands:
                results.append(invoke(command))
                spec.encode(results)
        return {'version': 1, 'results': results}
    finally:
        client.close()


def main():
    logging.disable(logging.CRITICAL)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024,) * 2)
    resource.setrlimit(resource.RLIMIT_CPU, (20, 20))
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
    resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
    try:
        value = spec.decode(sys.stdin.buffer.read(spec.MAX_JSON + 1))
        sys.stdout.buffer.write(spec.encode(execute(value)))
        sys.stdout.buffer.flush()
        return 0
    except IdentityChanged:
        sys.stderr.write('Windows endpoint identity changed.\n')
        return 2
    except Exception:
        sys.stderr.write('Windows transport request failed.\n')
        return 1
