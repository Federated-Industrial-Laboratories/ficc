# Access policy presets

These sources build separately signed runtime packages. They are not imported
by the host or compiled into its authorization rules.

`managed` supplies observer and operator roles for project resources.
`contribution` supplies read and preparation roles. It does not enable contributor
execution without executor and lease enforcement.

Build with `tools/pack-policy.py` and an operator-controlled Ed25519 key. Trust
the public key explicitly, install the archive, preview and activate. No signing
key is distributed. See [operation](../docs/policies.md) and [authoring](../sdk/policies.md).
