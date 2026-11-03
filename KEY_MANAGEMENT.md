# Key Management for the APT Repository

This document describes how the GPG signing key for the APT repository is
managed: how it is created, where it is stored, and how it is rotated.
It is aimed at repository maintainers — users of the APT repository only need
the [installation instructions](README.md#apt-repository-debianubuntu-amd64).

## Ground rules

The private signing key is the root of trust for every package installed from
this repository. Therefore:

1. **The private key only ever touches machines the maintainer personally
   controls.** It is never generated, stored, or pasted inside AI sessions,
   CI runners, repositories, tickets, or shared servers.
2. **Only the public key is published** (as `KEY.asc` on the APT repository).
3. **The key is dedicated to APT signing.** It is not a personal mail key and
   is not used for anything else.
4. **The key material is stored in exactly two places:** the maintainer's
   offline backup and the GitHub Actions secret `APT_GPG_PRIVATE_KEY`.
   No plaintext copies anywhere else — not even temporarily.
5. **Passphrases and private keys are never committed** to this repository.

## Status of the current key

> ⚠️ **The current key requires rotation.**
>
> The key with the fingerprint
> `6F4C8943B1EFF414077118767775F9CC2C0CE6FC` was generated inside a
> non-maintainer-controlled environment and its unencrypted private key was
> stored there in plaintext next to a GitHub access token. It must be
> considered potentially compromised. Use the [rotation
> procedure](#rotating-the-signing-key) below to replace it with a cleanly
> generated key.

## Creating a clean signing key

Perform all steps below **on your own trusted machine** (ideally while
offline). Nothing in this section involves GitHub, the repository, or any
server.

### 1. Generate the key

The key algorithm should be **Ed25519**. It is one of the three algorithms
modern apt explicitly supports for repository signing (RSA ≥ 2048, Ed25519,
Ed448 — everything else produces warnings/errors since apt 2.7.13 / Ubuntu
24.04), and it produces smaller, faster signatures than RSA. RSA 4096 is only
needed as a fallback for clients older than ~2017 (GnuPG < 2.1), which this
repository does not support.

Generate a single, dedicated, signing-only key:

```bash
gpg --quick-generate-key "OpsBox APT Repository <you@example.com>" ed25519 sign never
```

A more elaborate setup is possible — an offline certification-only master
key with a separate, expiring signing subkey, so the master key never enters
CI. That is deliberately **not** done here to keep the procedure simple; the
key is dedicated to this repository alone, which limits the blast radius.

### 2. Export the private key for CI

> ⚠️ **Compatibility note:** the current release workflow signs with
> `gpg --batch` without a passphrase. The exported key must therefore be
> **unprotected**. Do not add a passphrase yet — see
> [hardening](#hardening-options-not-yet-implemented) for the workflow changes
> a passphrase would require.

```bash
gpg --export-secret-keys --armor <FINGERPRINT>! > opsbox-apt-signing-key.asc
```

### 3. Store the public key and fingerprint for reference

```bash
gpg --export --armor <FINGERPRINT> > opsbox-apt-signing-key.pub.asc
gpg --fingerprint <FINGERPRINT>
```

Note the fingerprint — it must be documented in `opsbox-server-setup.sh`
(see the [rotation procedure](#rotating-the-signing-key)).

### 4. Upload the secret to GitHub

From your trusted machine with `gh` authenticated as a repository admin:

```bash
gh secret set APT_GPG_PRIVATE_KEY -R MarcSchuh/OpsBox < opsbox-apt-signing-key.asc
```

> The repo secret is readable by every workflow in this repository. That is
> acceptable for a dedicated, revocable, signing-only key. Moving the secret
> into a protected GitHub *environment* is listed under
> [hardening](#hardening-options-not-yet-implemented).

### 5. Delete the local plaintext export

```bash
rm opsbox-apt-signing-key.asc
```

Keep the private key only in your GPG keyring and your offline backup. After
verifying the next release (below), make sure no plaintext copy remains on
any machine.

### 6. Verify the release

Trigger a release (merge a PR to `main` or run the workflow manually), then
check that the published key matches your fingerprint:

```bash
curl -fsSL https://marcschuh.github.io/OpsBox/KEY.asc | gpg --show-keys
```

The output must show your key's fingerprint. Then verify the repository
metadata is actually signed with it:

```bash
curl -fsSL https://marcschuh.github.io/OpsBox/dists/stable/InRelease \
    | gpgv --keyring <(curl -fsSL https://marcschuh.github.io/OpsBox/KEY.asc | gpg --dearmor)
```

## Rotating the signing key

Use this procedure to replace the current (or a leaked) key.

1. **Create a clean key** as described in [creating a clean signing
   key](#creating-a-clean-signing-key) — steps 1–3.
2. **Overwrite the secret** with the new key material (step 4) and trigger a
   release. The workflow automatically publishes the new key as `KEY.asc` and
   re-signs `InRelease`/`Release.gpg` with it.
3. **Bridge the transition for existing servers.** Each release overwrites
   `KEY.asc` with *only* the new key, so servers configured with the old key
   will fail `apt update` until they fetch the new `KEY.asc`. Choose one:
   - **Manual (no workflow change needed):** after the first new release,
     locally export *both* keys and publish a combined `KEY.asc` to the
     `gh-pages` branch for one transition period:

     ```bash
     gpg --export --armor <OLD-FINGERPRINT> <NEW-FINGERPRINT> > KEY.asc
     # commit and push KEY.asc to the gh-pages branch
     ```

     The next regular release replaces it with the new key alone — by then
     servers should have re-run the setup script.
   - **Per server:** re-run `opsbox-server-setup.sh` (updated with the new
     fingerprint, see below) on each machine; it replaces the keyring entry.
4. **Document the new fingerprint.** Update the fingerprint line in
   `opsbox-server-setup.sh` and, if present, in the README, so fresh installs
   verify against the new key.
5. **Retire the old key.** Delete it from your keyring, and from any machine
   where it still exists (see [cleanup after the current
   rotation](#cleanup-after-the-current-rotation)). Since this key is not
   published on keyservers, no revocation is broadcast — the authoritative
   key list is `KEY.asc` itself.
6. **Clean up.** Ensure no plaintext copy of the old private key remains
   anywhere.

### Cleanup after the current rotation

For the key being replaced in this rotation specifically, also make sure the
unencrypted export that was used to bootstrap the secret in 2026-11 is
deleted from every workspace/server where it was stored, together with the
plaintext GitHub token file next to it. Treat both as compromised.

## If the key leaks

1. Immediately generate a clean replacement key (see above).
2. Overwrite `APT_GPG_PRIVATE_KEY`, trigger a release, and follow the
   [rotation procedure](#rotating-the-signing-key) including the transition
   bridge.
3. Audit the `gh-pages` history for tampered package files: `Packages`
   entries point into `pool/` — verify each `.deb` was published by a release
   workflow run.
4. Rotate the maintainer GitHub token(s) that were stored alongside the old
   key material.

## Hardening options (not yet implemented)

These changes improve the setup further but require workflow changes:

- **Environment secret:** move `APT_GPG_PRIVATE_KEY` into a protected GitHub
  environment `release` (required reviewers, deployment branch restricted to
  `main`) and add `environment: release` to the publish job in
  `.github/workflows/release.yml`. This limits which workflows can read the
  secret.
- **Passphrase-protected key:** export the key with a passphrase and store it
  in a second secret (e.g. `APT_GPG_PASSPHRASE`). The workflow must then
  import and sign with `--pinentry-mode loopback --passphrase
  "$APT_GPG_PASSPHRASE"`. A leaked key blob alone is then useless.
- **Key overlap by design:** adjust the `Publish APT repository` step to merge
  the freshly exported key into the existing `KEY.asc` instead of
  overwriting it, making rotations seamless for existing servers.
- **Pinned action SHAs:** reference third-party actions by full commit SHA
  instead of version tags.
