import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { normalizeDefaultTraffic } from "../src/stores/settingsStore.ts";

test("legacy and invalid fallback settings preserve automatic provider semantics", () => {
  assert.equal(normalizeDefaultTraffic(undefined, false), "auto");
  assert.equal(normalizeDefaultTraffic("invalid", false), "auto");
  assert.equal(normalizeDefaultTraffic("auto", false), "auto");
  assert.equal(normalizeDefaultTraffic("vpn", false), "vpn");
  assert.equal(normalizeDefaultTraffic("direct", false), "direct");
});

test("strict kill switch only normalizes an explicit Direct fallback", () => {
  assert.equal(normalizeDefaultTraffic("direct", true), "vpn");
  assert.equal(normalizeDefaultTraffic("auto", true), "auto");
  assert.equal(normalizeDefaultTraffic("vpn", true), "vpn");
});

test("routing fallback copy exists in both supported locales", () => {
  for (const language of ["ru", "en"]) {
    const locale = JSON.parse(
      readFileSync(`src/locales/${language}/translation.json`, "utf8")
    );
    const copy = locale.settings.routing.defaultTraffic;
    assert.equal(typeof copy.captureHint, "string");
    assert.equal(typeof copy.strictHint, "string");
    assert.equal(typeof copy.options.auto, "string");
    assert.equal(typeof copy.options.vpn, "string");
    assert.equal(typeof copy.options.direct, "string");
  }
});
