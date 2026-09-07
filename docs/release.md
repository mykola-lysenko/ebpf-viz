# Release Process

This repo publishes two release channels:

- `latest`: rolling prerelease rebuilt on every push to `main`.
- `vX.Y.Z`: versioned release created by pushing a matching Git tag.

The release workflow calls the same checks used by CI at the release commit:

- A dependency audit of the source `pnpm-lock.yaml`, including development tools.
- Node 22 typechecking, linting, tests, and build (`pnpm run ci:node22`).
- A standalone build on Node 22 and runtime smoke test on Node 16.20.2.

The audit runs in its own job so a failure does not prevent code validation.
For a complete local check, run both `pnpm audit` and `pnpm run ci:node22`.

Publishing requires all three jobs to pass. The release job downloads and
publishes the exact tarball uploaded after the smoke test; it does not rebuild
the package. These gates apply to both `main` pushes and version tags.

The standalone `package.json` is only an ESM marker. Its dependencies are
inlined into `server.js`, so running `npm audit` inside `standalone/` cannot
audit the bundled libraries. The source dependency audit is the release gate.

## Versioned Release Checklist

1. Update `package.json` to the target version.
2. Add a matching entry to `CHANGELOG.md`.
3. Merge or push the release commit to `main`.
4. Wait for `CI` and `Release Standalone Tarball` to pass on `main`.
5. Create and push the matching tag:

```bash
git tag v1.1.0
git push origin v1.1.0
```

The tag must match `package.json` exactly after removing the leading `v`.
For example, tag `v1.1.0` requires `"version": "1.1.0"`.

The versioned release uploads:

```text
ebpf-viz-standalone-vX.Y.Z.tar.gz
```

The rolling `latest` prerelease continues to upload:

```text
ebpf-viz-standalone.tar.gz
```
