# Repository Working Rules

## Dependency safety

- JavaScript dependencies may be installed only when every package is a known, necessary dependency already fixed by the exact reviewed lockfile, and only after reviewing its source, integrity metadata, maintainers, and lifecycle/install scripts. Prefer a disposable least-privilege runner and require explicit user approval before executing package code.
- Do not add random packages or use `npm update`, `npx`, `pnpm`, or `yarn` as a shortcut. Any dependency addition or version change requires explicit user approval and the same package-by-package review before the lockfile changes.
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
