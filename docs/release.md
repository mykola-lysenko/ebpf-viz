# Release Process

This repo publishes two release channels:

- `latest`: rolling prerelease rebuilt on every push to `main`.
- `vX.Y.Z`: versioned release created by pushing a matching Git tag.

The release workflow builds the standalone tarball on Node 22, then smoke-tests
the packaged runtime on Node 16.20.2 before publishing assets.

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

