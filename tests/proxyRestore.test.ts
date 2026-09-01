import assert from "node:assert/strict";
import test from "node:test";
import {
  extractProxyRestoreChallenge,
  connectFailurePresentation,
  ENTIRE_SESSION_RETAINED,
  errorHasCode,
  isUnsafeAutomaticProxyRestore,
  PROXY_RESTORE_CONFIRMATION_REQUIRED,
  PROXY_RESTORE_MANUAL_INTERVENTION_REQUIRED,
  preserveConnectionMetadataAfterCleanup,
  requiresProxyRestoreConfirmation,
  proxyRestoreConfirmationArgs,
  recoveryDialogOutcome,
  shouldKeepRecoveryDialogOpen,
} from "../src/lib/proxyRestore.ts";

test("recognizes the typed restore code in Tauri string errors", () => {
  const challenge = "123e4567-e89b-42d3-a456-426614174000";
  assert.equal(
    requiresProxyRestoreConfirmation(
      `disconnect failed [${PROXY_RESTORE_CONFIRMATION_REQUIRED}] challenge=${challenge}; confirm`
    ),
    true
  );
  assert.equal(
    extractProxyRestoreChallenge(
      `[${PROXY_RESTORE_CONFIRMATION_REQUIRED}] challenge=${challenge};`
    ),
    challenge
  );
});

test("recognizes wrapped Error and adapter error shapes", () => {
  const challenge = "123e4567-e89b-42d3-a456-426614174000";
  assert.equal(
    requiresProxyRestoreConfirmation(
      new Error(
        `${PROXY_RESTORE_CONFIRMATION_REQUIRED} challenge=${challenge};`
      )
    ),
    true
  );
  assert.equal(
    requiresProxyRestoreConfirmation({
      error: {
        cause: `${PROXY_RESTORE_CONFIRMATION_REQUIRED} challenge=${challenge};`,
      },
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
  assert.equal(
    requiresProxyRestoreConfirmation(PROXY_RESTORE_CONFIRMATION_REQUIRED),
    false
  );
  assert.equal(
    requiresProxyRestoreConfirmation(
      `${PROXY_RESTORE_CONFIRMATION_REQUIRED} challenge=not-a-uuid;`
    ),
    false
  );
  assert.equal(
    requiresProxyRestoreConfirmation(
      `[${PROXY_RESTORE_MANUAL_INTERVENTION_REQUIRED}] change Windows proxy manually`
    ),
    false
  );
});

test("handles cyclic error wrappers without recursing forever", () => {
  const wrapped: { cause?: unknown } = {};
  wrapped.cause = wrapped;
  assert.equal(requiresProxyRestoreConfirmation(wrapped), false);
});

test("detects explicit whole-session retention through Tauri wrappers", () => {
  assert.equal(
    errorHasCode(
      { error: { cause: `[${ENTIRE_SESSION_RETAINED}] retry later` } },
      ENTIRE_SESSION_RETAINED
    ),
    true
  );
  assert.equal(
    errorHasCode("entire_session_retained without brackets", ENTIRE_SESSION_RETAINED),
    false
  );
});

test("confirmed restore passes the one-use challenge with the exact IPC key", () => {
  const challenge = "123e4567-e89b-42d3-a456-426614174000";
  assert.deepEqual(proxyRestoreConfirmationArgs(challenge), { challenge });
});

test("unsafe recovery dispositions never offer an automatic restore", () => {
  assert.equal(isUnsafeAutomaticProxyRestore("manual_intervention_required"), true);
  assert.equal(isUnsafeAutomaticProxyRestore("foreign_state_pending"), true);
  assert.equal(isUnsafeAutomaticProxyRestore("unreadable"), true);
  assert.equal(isUnsafeAutomaticProxyRestore("confirmation_required"), false);
  assert.equal(isUnsafeAutomaticProxyRestore("automatic"), false);
});

test("explicit whole-session retention preserves metadata when status is unknown", () => {
  assert.equal(preserveConnectionMetadataAfterCleanup(null, true), true);
  assert.equal(preserveConnectionMetadataAfterCleanup(false, true), true);
  assert.equal(preserveConnectionMetadataAfterCleanup(null, false), false);
  assert.equal(preserveConnectionMetadataAfterCleanup(true, false), true);
});

test("crash dialog closes from refreshed recovery state only", () => {
  assert.equal(shouldKeepRecoveryDialogOpen({ was_crashed: false }), false);
  assert.equal(shouldKeepRecoveryDialogOpen({ was_crashed: true }), true);
});

test("retained connect rollback keeps Disconnect available despite a false or unknown probe", () => {
  const retained = `[${ENTIRE_SESSION_RETAINED}] connect failed; rollback incomplete`;
  assert.deepEqual(connectFailurePresentation(retained, null), {
    status: "running",
    cleanupPending: true,
    preserveConnectionMetadata: true,
  });
  assert.deepEqual(connectFailurePresentation(retained, false), {
    status: "running",
    cleanupPending: true,
    preserveConnectionMetadata: true,
  });
  assert.deepEqual(connectFailurePresentation("preflight rejected", false), {
    status: "error",
    cleanupPending: false,
    preserveConnectionMetadata: false,
  });
});

test("partial crash recovery keeps fresh findings and meaningful report errors", () => {
  assert.deepEqual(
    recoveryDialogOutcome(
      { was_crashed: true },
      ["TUN cleanup failed", "proxy still pending"]
    ),
    {
      keepOpen: true,
      error: "TUN cleanup failed; proxy still pending",
    }
  );
  assert.deepEqual(
    recoveryDialogOutcome({ was_crashed: false }, ["stale transient error"]),
    {
      keepOpen: true,
      error: "stale transient error",
    }
  );
  assert.deepEqual(recoveryDialogOutcome({ was_crashed: false }, []), {
    keepOpen: false,
    error: null,
  });
});
