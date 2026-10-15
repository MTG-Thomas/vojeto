# OCI release admission

Vojeto source is public and AGPL-3.0. The owner expressly selected a signed
public portable client to simplify delivery on October 15, 2026. Public client
images contain software, CA roots and license notices; tenant enrollment state,
keys, routes and provider configuration remain runtime inputs. The separate
router launcher retains its private-destination policy. Private Bifrost consumer
bundles and Azure deployment are owned by the infra repository.

## Producer boundary

Agents may dispatch ordinary releases without recurring human approval. Keep
the existing `vojeto-release` environment restricted to the single branch
`main`. Source review/merge, GitHub Verified exact current-main commits and
successful exact-source push `validate.yml` CI remain mandatory. The read-only
guard does not create environments, grant access or approve jobs. Optional
administrator-added GitHub gates still apply. Publication does not authorize
Azure deployment or production cutover.

Set `VOJETO_CLIENT_RELEASE_IMAGE=ghcr.io/mtg-thomas/vojeto`, the existing public
client destination. The client workflow explicitly requests public visibility;
public admission is limited to the owner-local package named `vojeto`. A public
launcher, foreign owner, internal package, mutable image input, stale source or
failed CI is refused. `VOJETO_LAUNCHER_RELEASE_IMAGE` remains an existing private
owner-local package; default admission remains private. No workflow changes
package visibility or creates a registry credential.

The workflow rechecks source and visibility immediately before publication.
Previously used full-source tags are rejected across paginated versions, and
concurrency serializes publishers. A successful push followed by failed signing
is not a qualified release. Preserve its receipt and publish a newly reviewed
source; never overwrite a source tag, re-sign unreviewed bytes or clear active
rollback artifacts. A failed/ambiguous mutation requires independent registry
readback before deciding what to do next.

The release targets require the dependency license inventory. Preserve the
source license and notices, including their redistribution obligations. Linux
amd64 is the qualified publication platform. ARM64 compilation and Windows
compilation are source evidence, not distributed runtime support. Windows
signing/private delivery requires its own acceptance if requested.

## Signing and consumer admission

Cosign 3.1.3 uses a commit-pinned installer with a pinned binary checksum.
GitHub OIDC obtains a short-lived keyless identity; no signing key or signing
credential is exported. Fulcio and transparency verification remain enabled.
The signature binds digest, source SHA and repository. The signed release
statement binds digest, source, exact workflow/ref, producer run and attempt,
platform, target, environment and signing identity/issuer.

Before consuming an image, run `python3 scripts/verify_release.py --image
<image@sha256:digest> --repository MTG-Thomas/vojeto --source <accepted-source>
--kind client` with pinned Cosign. Both cryptographic checks must pass before
statement admission. A successful push, public download or Git SHA tag alone
is insufficient. The producer verifies the same contract before reporting a
qualified release. Retain the immutable digest and producer receipt in infra.

Client pulls require no registry credential. This does not remove credentials
needed for private Bifrost bundles or other private images. Sigstore records
signing identity and artifact metadata publicly; never place tenant details or
secrets in image names, annotations or statements. Signature metadata does not
expose runtime inputs, which are not baked into the artifact.

Private launcher delivery must still prove authorized and unauthorized pulls
and its actual workload delivery path. No new ACR, paid registry, broad Azure
grant or long-lived credential is introduced by this public-client choice.

## Bootstrap failure and evidence limits

Private-client provisioning run `38799799447` pushed only
`vojeto-client-private:bootstrap-8b850b1847aa74e879cd6ccdaa245baae74d1fb4`, digest
`sha256:0fcf1479e757eff0ec46a052527436dfcb94b57fee0d86c1d9703d1b8988d785`.
Independent readback reported a public package and the post-push guard refused
it. Its sole version and creation timestamp were retained. No signed client
release or deployment was dispatched from that failed setup. Do not use this
unsigned bootstrap as a deployment pin. Existing public artifacts are unchanged.
The obsolete private-client provisioning workflow is retired; no package was
deleted or made public by a visibility-setting mutation.

GitHub documents that public packages cannot become private again. The owner
therefore selected the existing public client destination rather than another
private bootstrap path. Future privacy requirements need a separately reviewed
private delivery design; they must not be inferred from a package name or an
assumed registry default.

Policy tests cover exact main/CI, visibility, owner and immutable tag rejection.
Consumer tests cover changed digest/source/identity/target/platform and ensure
untrusted signatures do not reach statement admission. Offline synthetic Cosign
tests destroy their test-only key; transparency bypass is confined to that
synthetic test, never the OCI producer/consumer. Actual signed publication,
consumer verification and cloud lifecycle/rollback remain required before
calling Vojeto an accepted prototype replacement (issue #38).
