# FICC HTTPS audit provider

Install this wheel after FICC in the controller environment. It registers the
`ficc.audit` API1 `https` provider and supplies `ficc-audit-collector` for a
separately administered TLS destination. See `docs/audit.md` and `sdk/audit.md`
in the FICC distribution for configuration, append acknowledgements, required
admission and recovery.

The receiver acknowledges committed SQLite FULL/WAL appends and exact duplicate
batches. Its HTTP interface permits authenticated append only. Run it with private
durable storage under separate custody; controller-owned local files are not a
tamperproof destination. Credentials enter through private files or secret
references. No general log indexing, rotation or root-compromise protection is
provided.
