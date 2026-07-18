---
source: "common/secure-cicd.md"
title: "🚀 CI/CD Security (Secure CI/CD Pipeline)"
heading: "4. Artifact Signing"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [artifact, common-vuln, dependency, generation, pipeline, sbom, scanning, secret, security, signing]
chunk: 5/9
---

## 4. Artifact Signing

### Why Sign Artifacts?

- **Integrity**: Detect tampering between build and deploy
- **Provenance**: Prove who/what created the artifact
- **Non-repudiation**: Publisher cannot deny signing the release

### Tools

| Tool             | Standard         | Best For                |
|------------------|------------------|-------------------------|
| **Sigstore Cosign** | OIDC-based    | Container images, blobs |
| **GPG**          | PGP              | Git tags, traditional   |
| **minisign**     | Ed25519          | Lightweight, small bins |
| **notary**       | TUF framework    | Large-scale OTA updates |

### Cosign — Signing Container Images (CI)

```yaml
- name: Sign container image
  env:
    COSIGN_EXPERIMENTAL: 1  # keyless signing
  run: |
    cosign sign --yes ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}@${{ steps.digest.outputs.digest }}
```

### GPG — Signing Git Tags

```bash
# Configure signing
git config --global user.signingkey ABCDEF1234567890
git config --global commit.gpgsign true

# Sign a release
git tag -s v1.0.0 -m "Release v1.0.0"
git verify-tag v1.0.0
```

### Cosign — Verifying in CI

```yaml
- name: Verify signed artifact
  run: |
    cosign verify \
      --certificate-identity-regexp '^https://github.com/my-org/' \
      --certificate-oidc-issuer https://token.actions.githubusercontent.com \
      ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}@${{ steps.digest.outputs.digest }}
```

---