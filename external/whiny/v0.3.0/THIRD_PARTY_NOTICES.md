# Third-party notices

## dragoshont/winapi-vm-bridge

Whiny reuses and adapts committed development-plane source from
`https://github.com/dragoshont/winapi-vm-bridge`, branch `canonical-runtime`.

- License: Apache License 2.0
- License copy: [`third_party/winapi-vm-bridge/LICENSE`](third_party/winapi-vm-bridge/LICENSE)
- Verified source commits: `4e7827f`, `c7bffd8`, `cd0c397`, `f390678`,
  `d5b8e8999298282e5ff3e272a6e70a5c0d8c9525`
- Imported ownership: contract/IR algorithms, inspectors, generators,
  generator templates and source fixtures
- Excluded ownership: broker, pairing, authorization, transport, runtime hosts,
  Keychain/Wine seams, deployment and VM state

Per-file source paths and hashes are retained in the ownership ADR and component
provenance files. No generated `bin`, `obj`, `target`, runtime state,
credentials, private evidence or downloaded acceptance artifacts are imported.

Whiny itself does not yet declare a repository-wide redistribution license.
This notice records third-party terms and does not grant additional rights to
unlicensed Whiny-authored material.

