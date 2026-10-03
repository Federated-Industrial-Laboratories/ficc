# SPDX-License-Identifier: Apache-2.0
"""Use the signed HTTPS identity fixture for a real browser callback."""

import base64
import hashlib
import importlib.util
import os
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit

path = Path(os.environ["FICC_TEST_HOST_SOURCE"]) / "identity-providers/oidc/tests/issuer.py"
spec = importlib.util.spec_from_file_location("remote_stream_identity_fixture", path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class Identity(module.Issuer):
    def __init__(self, directory, callback):
        self.callback = callback
        self.subject_index = 0
        super().__init__(directory)
        original = self.server.RequestHandlerClass
        fixture = self

        class Handler(original):
            def do_GET(self):
                parsed = urlsplit(self.path)
                if parsed.path != "/authorize":
                    return super().do_GET()
                query = {key: values[0] for key, values in parse_qs(parsed.query).items()}
                if (query.get("redirect_uri") != fixture.callback
                        or query.get("client_id") != "ficc"
                        or query.get("code_challenge_method") != "S256"):
                    self.send_error(400)
                    return
                with fixture.lock:
                    code, _, _ = fixture.code(fixture.subject_index)
                    fixture.codes[code]["claims"]["nonce"] = query["nonce"]
                    fixture.codes[code]["challenge"] = query["code_challenge"]
                destination = fixture.callback + "?" + urlencode({
                    "state": query["state"], "code": code, "iss": fixture.issuer})
                self.send_response(303)
                self.send_header("Location", destination)
                self.send_header("Content-Length", "0")
                self.end_headers()

        self.server.RequestHandlerClass = Handler

    def respond(self, path, form):
        if path == "/token" and form and form.get("grant_type") == "authorization_code":
            with self.lock:
                record = self.codes.pop(form.get("code", ""), None)
                challenge = base64.urlsafe_b64encode(hashlib.sha256(
                    form.get("code_verifier", "").encode()).digest()).rstrip(b"=").decode()
                if (not record or record["challenge"] != challenge
                        or form.get("redirect_uri") != self.callback):
                    return 400, {"error": "invalid_grant"}
                return 200, self.tokens(record)
        return super().respond(path, form)
