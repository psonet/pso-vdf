# Security policy

## Release signing

Starting with the first release tagged after this file lands (expected: **v0.2.2**, the cog-bumped patch following PR `release/sigstore-signing`), every artifact attached to a `pso-vdf` GitHub Release is signed with [sigstore cosign](https://docs.sigstore.dev/cosign/overview/) keyless OIDC and carries an [SLSA v1.0](https://slsa.dev/spec/v1.0/) build-provenance attestation minted by `actions/attest-build-provenance`.

### Signed artifacts

For each release ≥ the cutoff, the following files ship alongside the regular release assets:

| File | What it is |
|---|---|
| `pso-vdf-X.Y.Z.crate` | The byte-identical .crate uploaded to crates.io. |
| `pso-vdf-X.Y.Z.crate.sig` | cosign blob signature (raw, base64). |
| `pso-vdf-X.Y.Z.crate.pem` | Fulcio-issued ephemeral signing cert (PEM). |
| `SHA256SUMS` | SHA-256 of the .crate. |
| `SHA256SUMS.sig` / `SHA256SUMS.pem` | cosign sig + cert for the manifest. |

Build-provenance attestations are not attached to the Release — they live in GitHub's attestation store and are queried via `gh attestation verify`.

### Threat model

The signing pipeline protects against:

- **Tampered binaries on the Release page.** A re-uploaded `.crate` or `SHA256SUMS` won't verify against the original cert + sig.
- **A compromised crates.io API token.** The same maintainer who can `cargo publish` cannot mint a sigstore signature whose Fulcio cert identity matches `https://github.com/psonet/pso-vdf/.github/workflows/ci.yml@refs/tags/vX.Y.Z`. That identity is only obtainable from inside a tag-triggered GitHub Actions run of this repo.
- **A typo or mis-targeted action update** silently weakening verification. The post-publish `verify-release` job hard-fails the workflow on any bad signature; an upstream change that breaks the cosign sign-blob flow is visible immediately.

It does **not** protect against:

- A compromise of `github.com/psonet/pso-vdf` itself (an attacker with push access to `main` can edit the workflow to remove or weaken signing).
- A compromise of the sigstore public-good trust root (Fulcio CA, Rekor transparency log).
- Tampering with the crates.io copy of the tarball. crates.io has no first-party signing channel; the GH-Release-attached `.crate` is byte-identical to the crates.io upload, so a paranoid consumer can `cargo fetch`, hash, and compare against `SHA256SUMS`.
- Existing (pre-cutoff) releases. Those are **not** retroactively signed.

### Verification recipe

You need [cosign](https://docs.sigstore.dev/cosign/installation/) and [`gh`](https://cli.github.com/) on `$PATH`.

```sh
REPO=psonet/pso-vdf
TAG=v0.2.2  # or any release ≥ the cutoff
ARTIFACT=pso-vdf-${TAG#v}.crate

gh release download "$TAG" --repo "$REPO" \
  --pattern "$ARTIFACT" \
  --pattern "$ARTIFACT.sig" \
  --pattern "$ARTIFACT.pem"

cosign verify-blob \
  --certificate "$ARTIFACT.pem" \
  --signature   "$ARTIFACT.sig" \
  --certificate-identity-regexp \
    '^https://github\.com/psonet/pso-vdf/\.github/workflows/ci\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "$ARTIFACT"

# Optional: SLSA build-provenance attestation.
gh attestation verify "$ARTIFACT" --repo "$REPO"
```

CI's own `verify-release` job runs the same loop on every published release; a green `verify-release` is your signal that the regex above is the correct one.

### Retroactive signing

Releases tagged **before** the cutoff are not signed. Backfilling would mint signatures whose Fulcio identity reads "a manual workflow_dispatch on YYYY-MM-DD by a maintainer," not "a tag-triggered run of the original release," which is weaker provenance than the absence of a signature.

## Reporting vulnerabilities

For security issues in `pso-vdf` itself (not the signing pipeline), open a [private security advisory](https://github.com/psonet/pso-vdf/security/advisories/new) on GitHub. Do not file a public issue.

## References

- [sigstore docs](https://docs.sigstore.dev/)
- [SLSA v1.0 specification](https://slsa.dev/spec/v1.0/)
- [`actions/attest-build-provenance`](https://github.com/actions/attest-build-provenance)
- [`sigstore/cosign-installer`](https://github.com/sigstore/cosign-installer)
