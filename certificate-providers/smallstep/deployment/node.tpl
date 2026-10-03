{{- if not (regexMatch "^[0-9a-f]{32}$" .Token.sub) -}}
{{ fail "Invalid node identifier" }}
{{- end -}}
{{- if ne (len .Token.sans) 1 -}}{{ fail "One node URI is required" }}{{- end -}}
{{- $identity := printf "urn:ficc:node:INSTALLATION_ID:%s" .Token.sub -}}
{{- if ne (index .Token.sans 0) $identity -}}{{ fail "Invalid node URI" }}{{- end -}}
{{- if not (and .Token.cnf (index .Token.cnf "x5rt#S256")) -}}
{{ fail "CSR binding is required" }}
{{- end -}}
{{- if typeIs "*ecdsa.PublicKey" .Insecure.CR.PublicKey -}}
{{- if ne .Insecure.CR.PublicKey.Curve.Params.Name "P-256" -}}
{{ fail "P-256 is required" }}
{{- end -}}
{{- else if not (typeIs "ed25519.PublicKey" .Insecure.CR.PublicKey) -}}
{{ fail "The node key type is unsupported" }}
{{- end -}}
{
  "subject": {"commonName": {{ toJson .Token.sub }}},
  "sans": [{"type": "uri", "value": {{ toJson $identity }}}],
  "keyUsage": ["digitalSignature"],
  "extKeyUsage": ["clientAuth"],
  "basicConstraints": {"isCA": false}
}
