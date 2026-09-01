export const PROXY_RESTORE_CONFIRMATION_REQUIRED =
  "proxy_restore_confirmation_required";
export const PROXY_RESTORE_MANUAL_INTERVENTION_REQUIRED =
  "proxy_restore_manual_intervention_required";
export const PROXY_RESTORE_FOREIGN_STATE_PENDING =
  "proxy_restore_foreign_state_pending";
export const ENTIRE_SESSION_RETAINED = "entire_session_retained";

export type ProxyRecoveryDisposition =
  | "none"
  | "automatic"
  | "confirmation_required"
  | "manual_intervention_required"
  | "foreign_state_pending"
  | "unreadable";

const CHALLENGE_PATTERN =
  /\bchallenge=([0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12});/i;

/**
 * Tauri normally rejects an invoke with a string, but test/dev adapters can
 * preserve an Error or wrap it in an `error`/`cause` field. Inspect only the
 * small, well-known error surface instead of stringifying arbitrary objects.
 */
export function extractProxyRestoreChallenge(error: unknown): string | null {
  const seen = new Set<object>();

  const findChallenge = (value: unknown, depth: number): string | null => {
    if (typeof value === "string") {
      if (!value.includes(PROXY_RESTORE_CONFIRMATION_REQUIRED)) return null;
      return value.match(CHALLENGE_PATTERN)?.[1]?.toLowerCase() ?? null;
    }
    if (value === null || typeof value !== "object" || depth >= 4) {
      return null;
    }
    if (seen.has(value)) return null;
    seen.add(value);

    if (value instanceof Error) {
      const challenge = findChallenge(value.message, depth + 1);
      if (challenge) return challenge;
    }

    const record = value as Record<string, unknown>;
    return (
      findChallenge(record.message, depth + 1) ??
      findChallenge(record.error, depth + 1) ??
      findChallenge(record.cause, depth + 1)
    );
  };

  return findChallenge(error, 0);
}

export function requiresProxyRestoreConfirmation(error: unknown): boolean {
  return extractProxyRestoreChallenge(error) !== null;
}

export function errorHasCode(error: unknown, code: string): boolean {
  const seen = new Set<object>();
  const visit = (value: unknown, depth: number): boolean => {
    if (typeof value === "string") return value.includes(`[${code}]`);
    if (value === null || typeof value !== "object" || depth >= 4) return false;
    if (seen.has(value)) return false;
    seen.add(value);
    if (value instanceof Error && visit(value.message, depth + 1)) return true;
    const record = value as Record<string, unknown>;
    return (
      visit(record.message, depth + 1) ||
      visit(record.error, depth + 1) ||
      visit(record.cause, depth + 1)
    );
  };
  return visit(error, 0);
}

export function proxyRestoreConfirmationArgs(challenge: string): {
  challenge: string;
} {
  return { challenge };
}

export function isUnsafeAutomaticProxyRestore(
  disposition: ProxyRecoveryDisposition
): boolean {
  return (
    disposition === "manual_intervention_required" ||
    disposition === "foreign_state_pending" ||
    disposition === "unreadable"
  );
}

export function preserveConnectionMetadataAfterCleanup(
  observedRunning: boolean | null,
  entireSessionRetained: boolean
): boolean {
  return entireSessionRetained || observedRunning === true;
}

export function shouldKeepRecoveryDialogOpen(refreshed: {
  was_crashed: boolean;
}): boolean {
  return refreshed.was_crashed;
}

export function connectFailurePresentation(
  error: unknown,
  observedRunning: boolean | null
): {
  status: "running" | "error";
  cleanupPending: boolean;
  preserveConnectionMetadata: boolean;
} {
  const cleanupPending = errorHasCode(error, ENTIRE_SESSION_RETAINED);
  return {
    // The backend marker is authoritative: a false/unknown process probe is
    // never permission to hide Disconnect while rollback ownership remains.
    status: cleanupPending || observedRunning === true ? "running" : "error",
    cleanupPending,
    preserveConnectionMetadata: cleanupPending || observedRunning === true,
  };
}

export function recoveryDialogOutcome(
  refreshed: { was_crashed: boolean },
  visibleErrors: string[]
): { keepOpen: boolean; error: string | null } {
  return {
    // A clean refreshed snapshot must not make report errors disappear before
    // the user can read them. Keep an empty-findings dialog open for explicit
    // acknowledgement whenever the recovery operation reported an error.
    keepOpen:
      shouldKeepRecoveryDialogOpen(refreshed) || visibleErrors.length > 0,
    error: visibleErrors.length > 0 ? visibleErrors.join("; ") : null,
  };
}
