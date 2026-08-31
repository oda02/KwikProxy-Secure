import assert from "node:assert/strict";
import test from "node:test";

import {
  AsyncMutex,
  AsyncSingleFlight,
  AttemptEpoch,
  MutationFence,
  isSameConnectionSelection,
  publishAfterCommit,
  publishRequiredTombstone,
  stopAndReconcile,
} from "../src/lib/asyncControl.ts";

test("a double connect shares one attempt", async () => {
  const gate = new AsyncSingleFlight();
  let starts = 0;
  let finish!: () => void;
  const blocked = new Promise<void>((resolve) => {
    finish = resolve;
  });

  const first = gate.run(async () => {
    starts += 1;
    await blocked;
  });
  const second = gate.run(async () => {
    starts += 1;
  });

  await Promise.resolve();
  assert.equal(starts, 1);
  assert.strictEqual(second, first);
  finish();
  await Promise.all([first, second]);
});

test("an early error releases the connect attempt for retry", async () => {
  const gate = new AsyncSingleFlight();
  let starts = 0;

  await assert.rejects(
    gate.run(async () => {
      starts += 1;
      throw new Error("early preflight failure");
    }),
    /early preflight failure/
  );

  await gate.run(async () => {
    starts += 1;
  });
  assert.equal(starts, 2);
});

test("a background runtime commit cannot invalidate an active receipt", async () => {
  const mutex = new AsyncMutex();
  const order: string[] = [];
  let markStarted!: () => void;
  const started = new Promise<void>((resolve) => {
    markStarted = resolve;
  });
  let finishConnect!: () => void;
  const blocked = new Promise<void>((resolve) => {
    finishConnect = resolve;
  });

  const connect = mutex.runExclusive(async () => {
    order.push("receipt");
    markStarted();
    await blocked;
    order.push("connect");
  });
  const backgroundCommit = mutex.runExclusive(async () => {
    order.push("background");
  });

  await started;
  assert.deepEqual(order, ["receipt"]);
  finishConnect();
  await Promise.all([connect, backgroundCommit]);
  assert.deepEqual(order, ["receipt", "connect", "background"]);
});

test("disconnect invalidates a late connect result", () => {
  const attempts = new AttemptEpoch();
  const connect = attempts.begin();
  const disconnect = attempts.cancel();

  assert.equal(attempts.isCurrent(connect), false);
  assert.equal(attempts.isCurrent(disconnect), true);
});

test("a late refresh cannot overwrite a newer connect attempt", async () => {
  const lifecycle = new AsyncMutex();
  const attempts = new AttemptEpoch();
  const observed = attempts.current();
  let releaseRefresh!: () => void;
  const refreshBlocked = new Promise<void>((resolve) => {
    releaseRefresh = resolve;
  });
  let visible = "initial";

  const refresh = lifecycle.runExclusive(async () => {
    await refreshBlocked;
    if (attempts.isCurrent(observed)) visible = "stale-refresh";
  });
  await Promise.resolve();
  const connectAttempt = attempts.begin();
  const connect = lifecycle.runExclusive(async () => {
    if (attempts.isCurrent(connectAttempt)) visible = "connected";
  });

  releaseRefresh();
  await Promise.all([refresh, connect]);
  assert.equal(visible, "connected");
});

test("backend cleanup retries and reconciles the observed stopped state", async () => {
  let stopCalls = 0;
  const observed = [true, false];
  const result = await stopAndReconcile(
    async () => {
      stopCalls += 1;
      if (stopCalls === 1) throw new Error("exact first stop error");
    },
    async () => observed.shift() ?? false
  );

  assert.equal(stopCalls, 2);
  assert.equal(result.stopped, true);
  assert.equal(result.observedRunning, false);
  assert.match(String(result.error), /exact first stop error/);
});

test("backend cleanup never reports stopped when reconciliation stays running", async () => {
  const exact = new Error("exact cleanup error");
  const result = await stopAndReconcile(
    async () => {
      throw exact;
    },
    async () => true
  );

  assert.equal(result.stopped, false);
  assert.equal(result.observedRunning, true);
  assert.strictEqual(result.error, exact);
});

test("backend cleanup reports unknown when the final state probe fails", async () => {
  const exact = new Error("exact status probe error");
  const result = await stopAndReconcile(
    async () => {},
    async () => {
      throw exact;
    }
  );

  assert.equal(result.stopped, false);
  assert.equal(result.observedRunning, null);
  assert.strictEqual(result.error, exact);
});

test("local primary is published only after its backend commit", async () => {
  const order: string[] = [];
  let release!: () => void;
  const blocked = new Promise<void>((resolve) => {
    release = resolve;
  });
  const pending = publishAfterCommit(
    async () => {
      await blocked;
      order.push("backend");
      return { generation: 7 };
    },
    () => order.push("local")
  );

  await Promise.resolve();
  assert.deepEqual(order, []);
  release();
  await pending;
  assert.deepEqual(order, ["backend", "local"]);
});

test("a rejected primary commit leaves the old local primary visible", async () => {
  let visible = "old-primary";
  const result = await publishAfterCommit(
    async () => null,
    () => {
      visible = "new-primary";
    }
  );

  assert.equal(result, null);
  assert.equal(visible, "old-primary");
});

test("same-index subscription refresh invalidates the connection selection", () => {
  const original = { name: "server-a" };
  const refreshed = { name: "server-a" };

  assert.equal(
    isSameConnectionSelection(
      { primaryId: "primary-a", selectedIndex: 0, server: original },
      { primaryId: "primary-a", selectedIndex: 0, server: refreshed }
    ),
    false
  );
  assert.equal(
    isSameConnectionSelection(
      { primaryId: "primary-a", selectedIndex: 0, server: original },
      { primaryId: "primary-a", selectedIndex: 0, server: original }
    ),
    true
  );
});

test("disconnect can wait until a cancelled single-flight becomes retryable", async () => {
  const gate = new AsyncSingleFlight();
  let finish!: () => void;
  const blocked = new Promise<void>((resolve) => {
    finish = resolve;
  });
  const connect = gate.run(async () => blocked);
  let idle = false;
  const disconnectWait = gate.waitForIdle().then(() => {
    idle = true;
  });

  await Promise.resolve();
  assert.equal(idle, false);
  finish();
  await Promise.all([connect, disconnectWait]);
  assert.equal(idle, true);
});

test("deletion publishes the captured tombstone before local reset", async () => {
  const order: string[] = [];
  let currentPrimary: string | null = "primary-a";
  const captured = currentPrimary;

  await publishRequiredTombstone(
    captured,
    async (id) => {
      order.push(`tombstone:${id}`);
    }
  );
  currentPrimary = null;
  order.push("reset");

  assert.deepEqual(order, ["tombstone:primary-a", "reset"]);
  assert.equal(currentPrimary, null);
});

test("failed deletion tombstone prevents local reset", async () => {
  let finalized = false;
  await assert.rejects(
    publishRequiredTombstone(
      "primary-a",
      async () => {
        throw new Error("set_servers failed exactly");
      }
    ).then(() => {
      finalized = true;
    }),
    /set_servers failed exactly/
  );
  assert.equal(finalized, false);
});

test("deletion fence rejects old queued and concurrent credential writes", () => {
  const fence = new MutationFence();
  const oldWrite = fence.snapshot();
  assert.notEqual(oldWrite, null);

  const deletion = fence.beginExclusive();
  assert.equal(fence.snapshot(), null);
  assert.equal(fence.allows(oldWrite!), false);

  fence.endExclusive(deletion);
  const freshWrite = fence.snapshot();
  assert.notEqual(freshWrite, null);
  assert.equal(fence.allows(freshWrite!), true);
});
