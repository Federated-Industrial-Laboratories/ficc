# FICC filesystem artifact provider

This trusted runtime distribution implements the version 1 `ficc.artifact`
interface for explicitly registered filesystem roots. It computes immutable
source identities and SHA-256 snapshots through the host's authorized file
transport and reads bounded ranges for dataset consumers.

Build with `python -m build --no-isolation artifact-providers/filesystem` from
the FICC source root, then install the resulting wheel into the controller's
Python environment and restart the controller. It has no additional runtime
dependencies or separate filesystem path configuration.

See [the dataset manual](../../docs/datasets.md) and
[the artifact SDK](../../sdk/artifacts.md). SQL, S3 and format parsing are outside
this package's interface. Registration does not copy or freeze a mutable source;
changed files fail verification and require a new dataset version.
