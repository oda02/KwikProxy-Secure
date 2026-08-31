import assert from "node:assert/strict";
import test from "node:test";
import { useToastStore } from "../src/stores/toastStore.ts";

function resetStore() {
  useToastStore.setState({ toasts: [] });
}

test("toast stack deduplicates repeated failures and keeps the newest three", () => {
  resetStore();
  const push = useToastStore.getState().push;

  push({ kind: "error", title: "Failed", message: "same failure", durationMs: 0 });
  const newestDuplicateId = push({
    kind: "error",
    title: "Failed",
    message: "same failure",
    durationMs: 0,
  });
  assert.equal(useToastStore.getState().toasts.length, 1);
  assert.equal(useToastStore.getState().toasts[0]?.id, newestDuplicateId);

  push({ kind: "info", message: "one", durationMs: 0 });
  push({ kind: "warning", message: "two", durationMs: 0 });
  push({ kind: "success", message: "three", durationMs: 0 });

  const toasts = useToastStore.getState().toasts;
  assert.equal(toasts.length, 3);
  assert.deepEqual(
    toasts.map((toast) => toast.message),
    ["one", "two", "three"]
  );
});

test("error notifications remain visible longer by default", () => {
  resetStore();
  const scheduled: number[] = [];
  Object.defineProperty(globalThis, "window", {
    configurable: true,
    value: {
      setTimeout: (_callback: () => void, delay: number) => {
        scheduled.push(delay);
        return 1;
      },
    },
  });

  const push = useToastStore.getState().push;
  push({ kind: "info", message: "info" });
  push({ kind: "error", message: "error" });

  assert.deepEqual(scheduled, [5_000, 10_000]);
  delete (globalThis as { window?: unknown }).window;
});
