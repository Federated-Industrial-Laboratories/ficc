# SPDX-License-Identifier: Apache-2.0
"""Load a private fixed kubeconfig without running authentication plugins."""

import fcntl
import os
import selectors
import signal
import ssl
import stat
import subprocess
import time
from http.client import HTTPSConnection
from pathlib import Path
from urllib.parse import urlsplit

from . import container_spec as spec
from .container_http import HTTP
from .file_access import opened


def memory(data):
    fd = os.memfd_create("ficc-container-config", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view):]
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
        return fd
    except BaseException:
        os.close(fd)
        raise


def convert(raw):
    try:
        return spec.decode(raw)
    except ValueError:
        if raw.lstrip().startswith((b"{", b"[")):
            raise
    binary = next((path for path in ("/usr/bin/kubectl", "/usr/local/bin/kubectl") if Path(path).is_file()), None)
    if binary is None:
        raise spec.ProviderError("container_kubeconfig", "Install kubectl to read a YAML kubeconfig, or store the same configuration as JSON.")
    fd = memory(raw)
    process = None
    try:
        process = subprocess.Popen([binary, "--kubeconfig", f"/proc/self/fd/{fd}", "config", "view", "--raw", "--merge=false", "-o", "json"],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, pass_fds=(fd,),
            env={"PATH": "/usr/bin:/bin", "HOME": str(Path.home()), "LANG": "C.UTF-8"}, start_new_session=True)
        assert process.stdout is not None
        output = bytearray()
        deadline = time.monotonic() + 5
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    raise ValueError("Kubeconfig parsing exceeded its deadline.")
                block = os.read(process.stdout.fileno(), 65536)
                if not block:
                    break
                output.extend(block)
                if len(output) > spec.MAX_MESSAGE:
                    raise ValueError("Kubeconfig parsing exceeded its byte limit.")
        if process.wait(timeout=max(0.1, deadline - time.monotonic())):
            raise ValueError("The kubeconfig could not be parsed.")
        return spec.decode(bytes(output))
    finally:
        os.close(fd)
        if process is not None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            assert process.stdout is not None
            process.stdout.close()


def selected(entries, name, key):
    if not isinstance(entries, list) or len(entries) > 128:
        raise ValueError("Invalid kubeconfig entries.")
    found = [item[key] for item in entries if isinstance(item, dict) and item.get("name") == name]
    if len(found) != 1:
        raise ValueError("The registered Kubernetes context is not unique or available.")
    return found[0]


def certificate(value):
    import base64
    spec.text(value, 131072)
    data = base64.b64decode(value, validate=True)
    if not data or len(data) > 65536:
        raise ValueError("The embedded certificate exceeds its size limit.")
    return data


def load(value):
    home = opened(-100, os.fsencode(Path.home()), os.O_RDONLY | os.O_DIRECTORY, False)
    try:
        fd = opened(home, b".kube/config", os.O_RDONLY)
    finally:
        os.close(home)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077 or info.st_nlink != 1 or info.st_size > 262144:
            raise ValueError("Use a private, owned kubeconfig no larger than 256 KiB.")
        raw = os.read(fd, 262145)
        if len(raw) != info.st_size:
            raise ValueError("The kubeconfig changed while it was read.")
    finally:
        os.close(fd)
    data = convert(raw)
    if data.get("kind") != "Config" or data.get("apiVersion") != "v1":
        raise ValueError("Invalid kubeconfig schema.")
    context = selected(data.get("contexts"), value["context"], "context")
    spec.fields(context, {"cluster", "user"}, {"namespace", "extensions"})
    cluster = selected(data.get("clusters"), context["cluster"], "cluster")
    user = selected(data.get("users"), context["user"], "user")
    # A strict allowlist refuses exec, auth-provider, tokenFile, impersonation,
    # external key paths, proxies and TLS verification overrides.
    spec.fields(cluster, {"server", "certificate-authority-data"}, {"extensions", "disable-compression"})
    if any(key in user for key in ("exec", "auth-provider", "tokenFile", "username", "password", "as", "as-uid", "as-groups", "as-user-extra")):
        raise spec.ProviderError("container_kubeconfig", "Use embedded credentials or a static token. Authentication plugins and impersonation are refused.")
    spec.fields(user, set(), {"token", "client-certificate-data", "client-key-data", "extensions"})
    if "extensions" in cluster or "extensions" in user or "extensions" in context:
        raise spec.ProviderError("container_kubeconfig", "Kubernetes context extensions are not supported.")
    server = urlsplit(spec.text(cluster["server"], 1024))
    if server.scheme != "https" or not server.hostname or server.username or server.password or server.query or server.fragment or server.path not in {"", "/"}:
        raise ValueError("Use a direct HTTPS Kubernetes API endpoint.")
    ca = certificate(cluster["certificate-authority-data"])
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    tls.minimum_version = ssl.TLSVersion.TLSv1_2
    tls.load_verify_locations(cadata=ca.decode("ascii"))
    headers = {}
    if "token" in user:
        if set(user) != {"token"}:
            raise ValueError("Select one static Kubernetes authentication method.")
        headers["Authorization"] = "Bearer " + spec.text(user["token"], 8192)
    else:
        if set(user) != {"client-certificate-data", "client-key-data"}:
            raise spec.ProviderError("container_kubeconfig", "Use an embedded client certificate or static token. Authentication plugins are refused.")
        cert_fd = memory(certificate(user["client-certificate-data"]))
        key_fd = None
        try:
            key_data = certificate(user["client-key-data"])
            if b"ENCRYPTED" in key_data:
                raise ValueError("Encrypted client keys are not supported.")
            key_fd = memory(key_data)
            tls.load_cert_chain(f"/proc/self/fd/{cert_fd}", f"/proc/self/fd/{key_fd}", password=lambda: b"")
        finally:
            os.close(cert_fd)
            if key_fd is not None:
                os.close(key_fd)
    binding = spec.digest({"context": value["context"], "namespace": value["namespace"], "cluster": cluster,
                           "user": user, "uid": os.getuid()})
    if value["binding"] is not None and value["binding"] != binding:
        raise spec.ProviderError("container_profile_changed", "The registered Kubernetes context or credentials changed.")
    http = HTTP(lambda: HTTPSConnection(server.hostname, server.port or 443, context=tls, timeout=4), headers)
    return http, binding
