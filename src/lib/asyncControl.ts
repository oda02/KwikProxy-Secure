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
