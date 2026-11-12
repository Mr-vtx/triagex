# Releasing Triagex

Releases are built by GitHub Actions from a tag. Nothing is built or uploaded by hand.

## Cut a release

1. Set the version in the root `Cargo.toml` (`[workspace.package] version`) and run `cargo build` so `Cargo.lock` updates.
2. Commit (`git commit -am "Release v0.1.0"`) and push to `main`. Wait for CI and the *Static build* workflow to go green.
3. **Dry run first**: `git tag v0.1.0-rc1 && git push origin v0.1.0-rc1`. This builds everything and publishes a *pre-release*. Check it, then delete it (on the Releases page, and `git push origin :refs/tags/v0.1.0-rc1`).
4. Real release: `git tag v0.1.0 && git push origin v0.1.0`.

The workflow refuses a tag that does not match the version in `Cargo.toml`.

## What a release contains

- `triagex-<tag>-x86_64-linux.tar.gz` and `triagex-<tag>-aarch64-linux.tar.gz`: a fully static binary, `LICENSE` and `README.md`. The archives are deterministic.
- `SHA256SUMS`: checksums for both archives.

## Verify a download

```sh
sha256sum --check --ignore-missing SHA256SUMS
```

`install.sh` does this automatically and refuses to install on a mismatch.

## What the checksums do and do not prove

They prove the download was not corrupted and that the archive matches what the release lists. They do not prove the release itself is authentic: whoever controls the repository controls both files. Signed releases are planned for a later version.
