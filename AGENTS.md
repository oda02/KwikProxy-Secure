# Repository Working Rules

## Dependency safety

- Do not run `npm install`, `npm ci`, `npm update`, `npx`, `pnpm`, `yarn`, or any command that downloads or executes JavaScript packages.
- Do not add or update npm dependencies without explicit user approval after reviewing the exact package, version, source, integrity metadata, maintainers, install scripts, and necessity.
- Treat npm lifecycle scripts and package binaries as untrusted code. Static inspection of `package.json` and `package-lock.json` is allowed.
- Prefer existing platform tools and repository code over adding dependencies.

## Privileged Windows testing

- Do not install or start the Kwik helper service, WinTUN, or the project installer on the host until the security boundary has been reviewed and hostile-client tests pass.
- Perform privileged integration tests in a disposable Windows VM or Windows Sandbox first.
- Never run bundled project executables merely to inspect them; use hashes, signatures, metadata, and static analysis.

## Change discipline

- Preserve subscription import, proxy mode, TUN mode, per-app routing, kill switch, crash recovery, install/update/uninstall, and current UI behavior unless a documented security requirement forces a change.
- Add regression and security tests for every trust-boundary change.
- Keep privileged APIs narrow: no caller-controlled executable paths, commands, or unrestricted filesystem locations.
