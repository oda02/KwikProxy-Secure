export const PROXY_RESTORE_CONFIRMATION_REQUIRED =
  "proxy_restore_confirmation_required";

/**
 * Tauri normally rejects an invoke with a string, but test/dev adapters can
 * preserve an Error or wrap it in an `error`/`cause` field. Inspect only the
 * small, well-known error surface instead of stringifying arbitrary objects.
 */
export function requiresProxyRestoreConfirmation(error: unknown): boolean {
  const seen = new Set<object>();

  const containsCode = (value: unknown, depth: number): boolean => {
    if (typeof value === "string") {
      return value.includes(PROXY_RESTORE_CONFIRMATION_REQUIRED);
    }
    if (value === null || typeof value !== "object" || depth >= 4) {
      return false;
    }
    if (seen.has(value)) return false;
    seen.add(value);

    if (value instanceof Error && containsCode(value.message, depth + 1)) {
      return true;
    }

    const record = value as Record<string, unknown>;
    return (
      containsCode(record.message, depth + 1) ||
      containsCode(record.error, depth + 1) ||
      containsCode(record.cause, depth + 1)
    );
  };

  return containsCode(error, 0);
}
