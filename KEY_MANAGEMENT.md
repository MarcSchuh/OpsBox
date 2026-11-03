# Key Management for the APT Repository

How the GPG signing key for the APT repository is created, stored, and
rotated. Aimed at repository maintainers — users of the APT repository only
need the [installation instructions](README.md#apt-repository-debianubuntu-amd64).

## Ground rules

The private signing key is the root of trust for every package installed from
this repository. Therefore:

1. **The private key only ever touches machines the maintainer personally
   controls.** It is never generated, stored, or pasted inside AI sessions,
   CI runners, repositories, tickets, or shared servers.
2. **Only the public key is published** (as `KEY.asc` on the APT repository).
3. **The key is dedicated to APT signing** — not a personal mail key.
4. **The key material lives in exactly two places:** the maintainer's offline
   backup and the GitHub Actions secret `APT_GPG_PRIVATE_KEY` (its passphrase
   in `APT_GPG_PASSPHRASE`). No plaintext copies anywhere else.
5. **Passphrases and private keys are never committed** to this repository.

## Current key

Active since 2026-11-03:

- Fingerprint: `02F0E92B05D8035B1AF8D43020FEAD66BB83E68C`
- Ed25519, sign-only, passphrase-protected

Its predecessor `6F4C8943B1EFF414077118767775F9CC2C0CE6FC` was rotated out on
2026-11-03: it had been generated in a non-maintainer-controlled environment
with the private key stored in plaintext.

## Creating a clean signing key

Perform all steps **on your own trusted machine** (ideally while offline).

### 1. Generate the key

The key algorithm should be **Ed25519** — one of the three algorithms modern
apt accepts for repository signing (RSA ≥ 2048, Ed25519, Ed448; everything
else produces warnings/errors since apt 2.7.13 / Ubuntu 24.04) — yielding
smaller, faster signatures than RSA:

```bash
gpg --quick-generate-key "OpsBox APT Repository <you@example.com>" ed25519 sign never
```

Choose a **passphrase** when prompted — so a leaked key blob alone is useless.
A more elaborate setup (offline certification master key with a separate,
expiring signing subkey) is possible but deliberately **not** used here; the
key is dedicated to this repository, which limits the blast radius.

### 2. Export the private key for CI

The export keeps the passphrase protection — that is intended. The release
workflow unlocks the key in CI using the passphrase from a second secret.

```bash
gpg --export-secret-keys --armor <FINGERPRINT>! > opsbox-apt-signing-key.asc
```

### 3. Upload the secrets to GitHub

From your trusted machine with `gh` authenticated as a repository admin:

```bash
gh secret set APT_GPG_PRIVATE_KEY -R MarcSchuh/OpsBox < opsbox-apt-signing-key.asc
gh secret set APT_GPG_PASSPHRASE -R MarcSchuh/OpsBox   # prompts for the passphrase
```

> The repo secrets are readable by every workflow in this repository. That is
> acceptable for a dedicated, revocable, signing-only key. Moving them into a
> protected GitHub *environment* is a listed
> [hardening option](#hardening-options).

### 4. Delete the local plaintext export

```bash
rm opsbox-apt-signing-key.asc
```

The private key now lives only in your GPG keyring and your offline backup.

### 5. Verify the release

Trigger a release (merge a PR to `main` or run the workflow manually), then
check that the published key matches your fingerprint:

```bash
curl -fsSL https://marcschuh.github.io/OpsBox/KEY.asc | gpg --show-keys
```

Then verify the repository metadata is actually signed with it:

```bash
curl -fsSL https://marcschuh.github.io/OpsBox/dists/stable/InRelease \
    | gpgv --keyring <(curl -fsSL https://marcschuh.github.io/OpsBox/KEY.asc | gpg --dearmor)
```

## Rotating the signing key

1. **Create a clean key** (steps 1–2 above), **overwrite both secrets**
   (step 3), and trigger a release. The workflow publishes the new key as
   `KEY.asc` and re-signs `InRelease`/`Release.gpg` with it.
2. **Bridge existing servers.** Every release overwrites `KEY.asc` with *only*
   the new key, so servers still holding the old key fail `apt update`.
   Either replace the keyring file on each server (re-run the setup), or
   publish a combined `KEY.asc` to the `gh-pages` branch for one transition
   period:

   ```bash
   gpg --export --armor <OLD-FINGERPRINT> <NEW-FINGERPRINT> > KEY.asc
   # commit and push to the gh-pages branch
   ```

3. **Retire the old key.** Delete it from your keyring and make sure no
   plaintext copy of it remains anywhere. This key is not published on
   keyservers — the authoritative key list is `KEY.asc` itself.
4. Record the new fingerprint under [Current key](#current-key) above.

## If the key leaks

1. Rotate immediately (see above) — treat it like any other rotation.
2. Audit the `gh-pages` history: verify every `.deb` in `pool/` was published
   by a release workflow run.
3. Rotate any GitHub tokens that had access to the secrets.

## Hardening options

Not yet implemented, in rough order of value:

- **Environment secrets:** move the signing secrets into a protected GitHub
  environment `release` (required reviewers, deployment branch restricted to
  `main`) and add `environment: release` to the publish job in
  `.github/workflows/release.yml`.
- **Key overlap by design:** adjust the `Publish APT repository` step to merge
  the freshly exported key into the existing `KEY.asc` instead of overwriting
  it, making rotations seamless for existing servers.
- **Pinned action SHAs:** reference third-party actions by full commit SHA
  instead of version tags.
