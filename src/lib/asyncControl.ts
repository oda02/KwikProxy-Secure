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
