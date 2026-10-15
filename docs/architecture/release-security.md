# Private OCI release admission

Source is public and AGPL-3.0. Future binary publication uses a separate private
destination and a main-restricted operator-dispatched release. The environment
exists; its approval transition, actual private keyless publication and deployed
private fetch tests still need runtime receipts. Existing published digests are
unchanged by these source edits.

## Asset and access matrix

| Asset | Current release path | Signing/admission | Remaining proof |
| --- | --- | --- | --- |
| Linux amd64 Vojeto OCI client | Private package supplied by `VOJETO_CLIENT_RELEASE_IMAGE` | Cosign keyless digest signature and signed release statement | Protected environment, authorized/unauthorized fetch, actual keyless producer/consumer verification |
| Linux amd64 router launcher OCI | Private package supplied by `VOJETO_LAUNCHER_RELEASE_IMAGE` | Same contract, separate workflow identity/target | Same delivery proof; launcher is not required for the worker adapter |
| Linux arm64 runtime | Compilation and rootless image defaults checked | Not published by these workflows | ARM64 execution and private signed multi-architecture producer |
| Windows peer executable | Compiled for source validation only | No distributed Windows asset | Azure Artifact Signing Public Trust, RFC 3161 timestamp and private delivery if Windows distribution is requested |
| Source, release notes and notices | Public Git repository | Signed source commit, preserved third-party obligations | No private enrollment state may be committed |

## Setup and producer checks

The owner authorizes agents to dispatch package provisioning and ordinary OCI
releases without a recurring human environment approval. Source review/merge,
Verified exact current-main commits and successful exact push CI remain the
admission boundary. Manual workflow dispatch does not mean a human must operate
it. Publication does not authorize deployment or production cutover.

Configure the existing `vojeto-release` environment with one deployment branch
policy of type `branch`, exactly `main`, and no required reviewers. Keep the
branch restriction, environment identity, credentials and scoped package grants.
The guard reads this environment; it does not create one, grant access, remove
rules or approve a pending job. Optional administrator-added reviewers or other
GitHub gates still apply; an agent never silently bypasses them. The old
`VOJETO_RELEASE_ALLOW_SELF_REVIEW` setting is unused and may be removed.

For the one-time transition, merge this policy and its tests, cancel the older
waiting publication run, remove only the existing required-reviewer rule while
preserving exact-main restrictions, then dispatch from the newly validated main.
Do not approve the superseded workflow or reuse its old-source preflight.
Azure deployment environments, repository review rules and other release lanes
are outside this change.

Provision each destination as an existing private GHCR container package owned
by the repository owner, grant this repository's Actions token the scoped write
access, and set the two repository variables to untagged
`ghcr.io/<owner>/<package>` names. The package's visibility and ownership are
checked before the publication job and again immediately before publication. Missing,
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
of workflow runs and package versions.

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

## One-time client destination provisioning

The configured `vojeto-client-private` destination must exist before the normal
signed client publisher can run. The manual `provision-client-destination.yml`
lane fills only this setup gap. It uses the same main-restricted `vojeto-release` environment,
exact verified current-main and successful exact push-CI requirements, without
recurring human approval. It never approves a job, changes protection rules,
adds a credential, or changes an
existing package's visibility/access. It handles only the configured owner-local
client destination, not the launcher or arbitrary package names.

After read-only metadata reports not-found, the admitted job builds the licensed
`release` target and makes one first-publish attempt under the repository's own
Actions token. A 404 is not proof that an inaccessible package does not exist;
the registry must still authorize this repository's write. Other errors and
already-readable destinations stop the lane. It then requires independent
readback of private visibility, exact owner and repository association. A failed
or ambiguous push must be reconciled by metadata readback, never blindly rerun.

The only setup tag is `bootstrap-<full-source-SHA>`. It is not a qualified signed
release or a deployment pin. Preserve its receipt and run the normal protected
client publisher afterward; the existing private-package, signing, attestation,
source-tag and consumer-admission requirements still apply. No existing public
artifact is retagged or changed. Provisioning creates no Azure resource or
standing network capacity. Normal release admission also rechecks the live main
SHA, so a source superseded before publication cannot publish.
