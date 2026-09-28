# SPDX-License-Identifier: Apache-2.0
"""Select fixed display controls for private VNC and VMConnect transports."""


def settings(config, port, arguments):
    values = {"hostname": "127.0.0.1", "port": str(port), "read-only": "false",
              "disable-copy": "true", "disable-paste": "true", "enable-sftp": "false",
              "color-depth": "24", "force-lossless": "true"}
    required = set(values) - {"enable-sftp"}
    if config["protocol"] == "vnc":
        values.update({"enable-audio": "false", "swap-red-blue": "false", "cursor": "remote", "autoretry": "0"})
        required.add("autoretry")
        if "password" in config:
            values["password"] = config["password"]
            required.add("password")
    elif config["protocol"] == "rdp":
        values.update({"security": "vmconnect", "preconnection-blob": config["vm_id"],
            "username": config["username"], "password": config["password"], "domain": config["domain"],
            "cert-fingerprints": "sha256:" + config["certificate_sha256"],
            "ignore-cert": "false", "cert-tofu": "false", "disable-auth": "false",
            "disable-audio": "true", "enable-audio-input": "false", "console-audio": "false",
            "enable-printing": "false", "enable-drive": "false", "enable-touch": "false",
            "disable-download": "true", "disable-upload": "true", "create-drive-path": "false",
            "create-recording-path": "false", "recording-write-existing": "false",
            "wol-send-packet": "false", "resize-method": "display-update", "timeout": "8"})
        required |= {"security", "preconnection-blob", "username", "password", "domain", "cert-fingerprints",
            "ignore-cert", "cert-tofu", "disable-auth", "disable-audio", "enable-audio-input",
            "enable-printing", "enable-drive"}
    else:
        raise ValueError("Unsupported display protocol.")
    if not required <= set(arguments):
        raise ValueError("The display daemon lacks the required controls.")
    return values
