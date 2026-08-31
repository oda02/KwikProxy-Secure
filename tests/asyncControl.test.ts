import assert from "node:assert/strict";
import test from "node:test";

import { AsyncMutex, AsyncSingleFlight } from "../src/lib/asyncControl.ts";

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
