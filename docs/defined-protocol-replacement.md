# Defined protocol replacement

Scope: source readiness for the main Vojeto client; no platform deployment.

Vojeto independently implements its existing enrollment and update contract in
`internal/definedwire`. Implementation uses Go's standard crypto/X.509/PEM
packages, Nebula's MIT raw-key PEM codecs, and the existing licensed YAML v3
dependency. No Defined SDK implementation or tests were copied into this package.
This is not a clean-room claim: the SDK's wire formats were inspected to identify
interoperability requirements. Endpoint paths, JSON field names, PEM labels,
key encodings and signature representations are protocol compatibility facts.
The SDK is removed from go.mod, go.sum and all production/test imports.

Requests sign the base64 text of the inner JSON message. Signed responses verify
the decoded raw message bytes. Ed25519 signs directly; P256 uses SHA-256 and ASN.1
ECDSA signatures. Host signing keys use X.509 DER in Defined PEM labels. Trusted
signing keys and independent Nebula identity keys use Nebula raw-key PEM labels.
P256 keys are generated in every mode; Ed25519/X25519 generation is disabled when
Go FIPS mode is enabled. The existing checkpoint version and serialized fields
remain unchanged, including host private-key and trusted-key PEM encodings.

The existing bounded HTTP client remains responsible for request limits, timeout,
redirect rejection, response verification, nonce/counter checks, trusted-key
rotation, enrollment validation and persistence. YAML insertion preserves the
configuration while replacing pki.key, and rejects duplicate relevant mappings
and multiple documents. It does not accept a missing or non-mapping pki section.

Verification performed for this change:

- Existing Defined and Azure provider tests pass with race detection.
- RFC 8032 Ed25519 known-answer verification and signature representation checks.
- Both curves pass private-key and trusted-key roundtrips and tampering checks.
- An external temporary interoperability harness used the previously pinned SDK
  solely as a local test tool: old key PEM decodes in the replacement, new PEM
  decodes in the SDK, each verifier accepts the other's signed request, and
  trusted-key bundles roundtrip in both directions. The SDK/harness is excluded
  from this repository and every release dependency.
- Native main-client build and complete linked-module notice inventory pass.
- CI now builds the main `release` target so its notice gate is mandatory.

The container release gate and reviewer assessment must pass before publication.
This change proves neither live Defined enrollment/rotation nor ACA acceptance.
Real staging must exercise enrollment, rotation, restart/checkpoint recovery,
required dependency TLS probes, identity exclusivity, and graceful drain before
replacing the prototype. Existing launcher publication does not establish these
main-client claims.
