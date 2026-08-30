// Build the development helper without touching the installed Windows service.
//
// The secure fork never elevates from a development/runtime script. A locked
// target is an error: service lifecycle belongs to the per-machine installer,
// and privileged testing must happen in a disposable Windows VM first.

import { spawnSync } from "node:child_process";

const result = spawnSync(
  "cargo",
  [
    "build",
    "--locked",
    "--manifest-path",
    "src-tauri/Cargo.toml",
    "--bin",
    "kwik-helper",
  ],
  {
    stdio: "inherit",
    shell: false,
  },
);

if (result.error) {
  console.error(`[build-helper] cargo could not be started: ${result.error.message}`);
}

process.exit(result.status ?? 1);
