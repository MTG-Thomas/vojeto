# Private OCI release admission

Source is public and AGPL-3.0. Future binary publication uses a separate private
destination and a protected manual release. This is a source implementation;
protected environment setup, actual keyless publication and deployed private
fetch tests have not been completed. Existing published digests are unchanged.

## Asset and access matrix

| Asset | Current release path | Signing/admission | Remaining proof |
| --- | --- | --- | --- |
| Linux amd64 Vojeto OCI client | Private package supplied by `VOJETO_CLIENT_RELEASE_IMAGE` | Cosign keyless digest signature and signed release statement | Protected environment, authorized/unauthorized fetch, actual keyless producer/consumer verification |
| Linux amd64 router launcher OCI | Private package supplied by `VOJETO_LAUNCHER_RELEASE_IMAGE` | Same contract, separate workflow identity/target | Same delivery proof; launcher is not required for the worker adapter |
| Linux arm64 runtime | Compilation and rootless image defaults checked | Not published by these workflows | ARM64 execution and private signed multi-architecture producer |
| Windows peer executable | Compiled for source validation only | No distributed Windows asset | Azure Artifact Signing Public Trust, RFC 3161 timestamp and private delivery if Windows distribution is requested |
| Source, release notes and notices | Public Git repository | Signed source commit, preserved third-party obligations | No private enrollment state may be committed |

## Setup and producer checks

Before a release, an administrator must explicitly configure `vojeto-release`
with required reviewers and one deployment branch policy of type `branch`,
exactly `main`. Self-review prevention is required by default. An operator may
explicitly select manual approval by the initiating account: set repository
variable `VOJETO_RELEASE_ALLOW_SELF_REVIEW=true` and disable the environment’s
self-review prevention. This permits one person to initiate and manually approve
a run; it provides no independent-review guarantee. Required reviewers remain
mandatory, and the agent never submits the human approval. Missing protection
or reviewer metadata still fails closed. Invalid opt-in values are rejected.
The guard reads the environment; it does not create one or grant access.

Provision each destination as an existing private GHCR container package owned
by the repository owner, grant this repository's Actions token the scoped write
access, and set the two repository variables to untagged
`ghcr.io/<owner>/<package>` names. The package's visibility and ownership are
checked before the approval job and again immediately before publication. Missing,
public, internal, foreign or unreadable packages fail closed. No visibility
change, public artifact upload or Azure resource is created by these workflows.

The manual dispatch's expected SHA must equal the actual `main` workflow source,
be reported Verified by GitHub and have a successful exact-source push run of
`validate.yml`. Previously used source tags are rejected, including across
paginated package versions. Concurrency prevents two publishers in one lane from
moving a tag. If a push succeeds but signing/attestation fails, that tag is not a
qualified release and cannot be overwritten by a retry. Preserve the failed
receipt and publish a newly reviewed source rather than silently replacing it.

The normal release Docker targets still require the complete dependency notice
inventory. Images contain portable software, with rootless defaults; no tenant
enrollment state, routes, SASs, provider credentials or private configuration is
baked into them. Their SHA-256 OCI digest is the artifact checksum.

Cosign 3.1.3 is installed by an action pinned to a full commit with a pinned binary
checksum. GitHub OIDC obtains short-lived signing identity; no signing key export
or long-lived signing credential is stored. Fulcio and transparency verification
remain enabled for real OCI releases. The signature binds source SHA/repository;
the signed release statement binds OCI digest, source, workflow/ref, CI run and
attempt, platform, target, protected environment and signing identity/issuer.
The producer verifies both before reporting success.

Sigstore's public transparency infrastructure records signing metadata and
digests. It does not make private image bytes downloadable. Image/package names,
source and CI identity metadata must therefore be safe to disclose; never place
tenant identifiers or credentials in them. Expected initial signing volume is
two OCI artifacts per reviewed release, plus their statements; this is a planning
assumption, not measured consumption. Unexpected release counts require review
of workflow runs, approvals and package versions.

## Consumer and platform delivery

Authenticate to the private registry through the reviewed delivery adapter, then
run `python3 scripts/verify_release.py --image <image@sha256:digest>
--repository <owner/repo> --source <reviewed-commit> --kind client` with the pinned
Cosign tool available. The helper requires the exact workflow identity, GitHub
issuer, commit and manual-dispatch claim, and checks the signed statement only
after cryptographic signature/attestation verification. It makes no deployment
or trust-setting changes. The infra operator must reject a failing result before
preview/admission and retain the evidence with its immutable pin.

GHCR preparation does not establish ACA workload-identity image delivery. A
platform with native Entra/managed-identity pulls may need a separately approved
private ACR destination and OIDC grants. No long-lived registry secret, new paid
registry or broad Azure grant is introduced here. The private infra lane must
select and verify its actual delivery path, including an authorized pull from
the declared workload and a rejected unauthorized pull, before cutover. Repository
metadata and a local Docker login do not prove those properties.

## Failure, rollback and revocation

Consumers pin both digest and accepted source. For releases admitted under this
policy, rollback selects a previously accepted private digest with its verified
receipt, following the environment's drain and checkpoint runbook. Never select
an unsigned tag, re-sign unreviewed bytes, clear quarantined identities or move an
existing source tag to make rollback start. Legacy prototype rollback remains
under its recorded private deployment policy until the replacement is accepted;
it is not retrospectively certified by this publisher.

For a compromised workflow/identity or withdrawn source, stop publication at the
protected environment, revoke its package grant and deny the exact source/digest
in the private deployment admission policy. Retain receipts and the accepted
rollback digest. Short-lived certificates are verified with transparency evidence;
do not pin a rotating leaf-certificate thumbprint or disable verification to
recover. Registry retention/deletion must preserve every active and rollback pin
and use the deployment repository's explicit cleanup authorization.

## Evidence limits

Policy tests reject unprotected/wrong-ref/public/foreign inputs. Consumer tests
reject changed source, digest, identity, target, platform and empty evidence and
prove that an untrusted signature never reaches statement admission. The offline
synthetic Cosign test verifies a generated fixture and rejects modified content;
its test-only key is destroyed on exit. Ignoring a transparency log is restricted
to that synthetic offline fixture, never the OCI producer or consumer.

These checks do not replace actual protected keyless publication, registry
authorization readback, cloud pull testing, deployment admission or rollback
acceptance. Track that remaining evidence in issue #38 and the production
acceptance contract before calling Vojeto production-ready.
