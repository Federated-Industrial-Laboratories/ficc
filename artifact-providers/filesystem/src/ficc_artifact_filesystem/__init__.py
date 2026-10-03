# SPDX-License-Identifier: Apache-2.0
"""Resolve ordinary files through the host's authorized filesystem capability."""

API_VERSION = 1


def configure(configuration):
    if configuration:
        raise ValueError("The registered filesystem provider has no separate path configuration.")
    return Filesystem()


class Filesystem:
    async def snapshot(self, capability):
        info, _ = await capability.call("file.stat")
        if info["kind"] != "file":
            raise ValueError("Select a regular file as a dataset source.")
        hashed, _ = await capability.call("file.hash")
        return {"name": info["name"], "size": hashed["size"], "sha256": hashed["sha256"],
                "identity": info["reference"]["identity"]}

    async def read(self, capability, offset, limit):
        return await capability.call("file.read", offset=offset, limit=limit)
