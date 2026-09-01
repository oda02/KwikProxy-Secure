/**
 * Shares one asynchronous attempt between all callers until it settles.
 * A rejected attempt is released in `finally`, so the next call is a retry.
 */
export class AsyncSingleFlight {
  private inFlight: Promise<void> | null = null;

  run(task: () => Promise<void>): Promise<void> {
    if (this.inFlight) return this.inFlight;

    const attempt = Promise.resolve().then(task);
    const shared = attempt.finally(() => {
      if (this.inFlight === shared) this.inFlight = null;
    });
    this.inFlight = shared;
    return shared;
  }

  waitForIdle(): Promise<void> {
    return this.inFlight ?? Promise.resolve();
  }
}

/** A small FIFO mutex for frontend operations that must not overtake. */
export class AsyncMutex {
  private tail: Promise<void> = Promise.resolve();

  async runExclusive<T>(task: () => Promise<T>): Promise<T> {
    const previous = this.tail;
    let release!: () => void;
    this.tail = new Promise<void>((resolve) => {
      release = resolve;
    });

    await previous.catch(() => {});
    try {
      return await task();
    } finally {
      release();
    }
  }
}

/** Monotonic token used to invalidate a late asynchronous result. */
export class AttemptEpoch {
  private epoch = 0;

  begin(): number {
    this.epoch += 1;
    return this.epoch;
  }

  cancel(): number {
    return this.begin();
  }

  isCurrent(attempt: number): boolean {
    return this.epoch === attempt;
  }

  current(): number {
    return this.epoch;
  }
}

/** Generation fence for destructive finalization versus queued mutations. */
export class MutationFence {
  private epoch = 0;
  private blocked = false;

  snapshot(): number | null {
    return this.blocked ? null : this.epoch;
  }

  beginExclusive(): number {
    if (this.blocked) throw new Error("destructive mutation is already active");
    this.blocked = true;
    this.epoch += 1;
    return this.epoch;
  }

  endExclusive(token: number): void {
    if (this.epoch === token) this.blocked = false;
  }

  allows(snapshot: number): boolean {
    return !this.blocked && snapshot === this.epoch;
  }

  isBlocked(): boolean {
    return this.blocked;
  }
}

export type BackendStopResult = {
  stopped: boolean;
  cleanupSucceeded: boolean;
  observedRunning: boolean | null;
  error: unknown | null;
};

/**
 * Stop a backend and verify the observed state. A failed stop is retried, and
 * an unknown final state is treated as still running rather than reporting a
 * false-safe stopped UI.
 */
export async function stopAndReconcile(
  stop: () => Promise<void>,
  isRunning: () => Promise<boolean>,
  maxAttempts = 2
): Promise<BackendStopResult> {
  let firstError: unknown | null = null;
  let observedRunning: boolean | null = null;
  for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
    // The stop call can change backend state, so an observation from the
    // previous attempt is no longer evidence about the final state.
    observedRunning = null;
    let stopSucceeded = false;
    try {
      await stop();
      stopSucceeded = true;
    } catch (error) {
      firstError ??= error;
    }
    try {
      observedRunning = await isRunning();
      if (!observedRunning && stopSucceeded) {
        return {
          stopped: true,
          cleanupSucceeded: true,
          observedRunning: false,
          error: firstError,
        };
      }
    } catch (error) {
      firstError ??= error;
    }
  }
  return {
    stopped: observedRunning === false,
    cleanupSucceeded: false,
    observedRunning,
    error: firstError ?? new Error("backend remained running after cleanup"),
  };
}

/**
 * Invoke a non-idempotent stop exactly once, then perform only bounded status
 * polling. This is required for one-use confirmation receipts: retrying the
 * command would replay an already-consumed receipt, while a short status poll
 * still allows an asynchronously exiting backend to become observable.
 */
export async function stopOnceAndReconcile(
  stop: () => Promise<void>,
  isRunning: () => Promise<boolean>,
  maxStatusAttempts = 3,
  pollDelayMs = 75
): Promise<BackendStopResult> {
  let firstError: unknown | null = null;
  let stopSucceeded = false;
  let observedRunning: boolean | null = null;

  try {
    await stop();
    stopSucceeded = true;
  } catch (error) {
    firstError = error;
  }

  const attempts = Math.max(1, maxStatusAttempts);
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    try {
      observedRunning = await isRunning();
      if (!observedRunning) break;
    } catch (error) {
      firstError ??= error;
      observedRunning = null;
    }
    if (attempt + 1 < attempts && pollDelayMs > 0) {
      await new Promise((resolve) => setTimeout(resolve, pollDelayMs));
    }
  }

  if (stopSucceeded && observedRunning === false) {
    return {
      stopped: true,
      cleanupSucceeded: true,
      observedRunning: false,
      error: firstError,
    };
  }
  return {
    stopped: observedRunning === false,
    cleanupSucceeded: false,
    observedRunning,
    error:
      firstError ?? new Error("backend remained running after one-use cleanup"),
  };
}

/** Publish local state only after an asynchronous backend commit succeeds. */
export async function publishAfterCommit<T>(
  commit: () => Promise<T | null>,
  publish: (receipt: T) => void
): Promise<T | null> {
  const receipt = await commit();
  if (receipt === null) return null;
  publish(receipt);
  return receipt;
}

/** Delete sequentially and restore already deleted entries on any failure. */
export async function deleteWithRollback<T>(
  entries: readonly T[],
  remove: (entry: T) => Promise<void>,
  restore: (entry: T) => Promise<void>
): Promise<void> {
  try {
    for (const entry of entries) {
      await remove(entry);
    }
  } catch (error) {
    const rollbackErrors: unknown[] = [];
    // The failing remove may have committed remotely before its response was
    // lost. Restore the complete pre-snapshot, not only acknowledged deletes.
    for (const entry of [...entries].reverse()) {
      try {
        await restore(entry);
      } catch (rollbackError) {
        rollbackErrors.push(rollbackError);
      }
    }
    if (rollbackErrors.length > 0) {
      throw new Error(
        `${String(error)}; credential rollback failed: ${rollbackErrors
          .map(String)
          .join("; ")}`
      );
    }
    throw error;
  }
}

export function choosePersistedById<T extends { id: string }>(
  entries: readonly T[],
  persistedId: string | null
): T | undefined {
  return entries.find((entry) => entry.id === persistedId) ?? entries[0];
}

export type OptionalRead<T> =
  | { kind: "value"; value: T }
  | { kind: "missing" }
  | { kind: "error"; error: unknown };

export async function readOptional<T>(
  read: () => Promise<T>,
  isMissing: (value: T) => boolean
): Promise<OptionalRead<T>> {
  try {
    const value = await read();
    return isMissing(value) ? { kind: "missing" } : { kind: "value", value };
  } catch (error) {
    return { kind: "error", error };
  }
}

export function optionalValueOrThrow<T>(
  result: OptionalRead<T>,
  required: boolean
): T | null {
  if (result.kind === "error") {
    if (required) throw result.error;
    return null;
  }
  return result.kind === "value" ? result.value : null;
}

export async function withAsyncRollback<T>(
  operation: () => Promise<T>,
  rollback: () => Promise<void>,
  label: string
): Promise<T> {
  try {
    return await operation();
  } catch (error) {
    try {
      await rollback();
    } catch (rollbackError) {
      throw new Error(
        `${String(error)}; ${label} rollback failed: ${String(rollbackError)}`
      );
    }
    throw error;
  }
}

export type ConnectionSelection<T> = {
  primaryId: string | null;
  selectedIndex: number | null;
  server: T | undefined;
};

/** Object identity also catches a same-index server list refresh. */
export function isSameConnectionSelection<T>(
  expected: ConnectionSelection<T>,
  current: ConnectionSelection<T>
): boolean {
  return (
    expected.primaryId === current.primaryId &&
    expected.selectedIndex === current.selectedIndex &&
    expected.server === current.server
  );
}

/** Publish a captured tombstone before destructive local finalization begins. */
export async function publishRequiredTombstone<T>(
  snapshot: T | null,
  publish: (snapshot: T) => Promise<void>
): Promise<void> {
  if (snapshot !== null) await publish(snapshot);
}
