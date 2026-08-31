import assert from "node:assert/strict";
import test from "node:test";
import {
  PROXY_RESTORE_CONFIRMATION_REQUIRED,
  requiresProxyRestoreConfirmation,
} from "../src/lib/proxyRestore.ts";

test("recognizes the typed restore code in Tauri string errors", () => {
  assert.equal(
    requiresProxyRestoreConfirmation(
      `disconnect failed [${PROXY_RESTORE_CONFIRMATION_REQUIRED}]: confirm`
    ),
    true
  );
});

test("recognizes wrapped Error and adapter error shapes", () => {
  assert.equal(
    requiresProxyRestoreConfirmation(
      new Error(PROXY_RESTORE_CONFIRMATION_REQUIRED)
    ),
    true
  );
  assert.equal(
    requiresProxyRestoreConfirmation({
      error: { cause: PROXY_RESTORE_CONFIRMATION_REQUIRED },
    }),
    true
  );
});

test("does not prompt for unrelated cleanup failures", () => {
  assert.equal(
    requiresProxyRestoreConfirmation(new Error("mihomo stop timed out")),
    false
  );
  assert.equal(requiresProxyRestoreConfirmation(null), false);
});

test("handles cyclic error wrappers without recursing forever", () => {
  const wrapped: { cause?: unknown } = {};
  wrapped.cause = wrapped;
  assert.equal(requiresProxyRestoreConfirmation(wrapped), false);
});
