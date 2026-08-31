import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import {
  normalizeDefaultTraffic,
  normalizeImportedDefaultTraffic,
} from "../src/stores/settingsStore.ts";

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

test("backup preview and roundtrip expose strict Direct coercion", () => {
  const current = {
    killSwitch: false,
    killSwitchStrict: false,
    defaultTraffic: "auto" as const,
  };
  const imported = normalizeImportedDefaultTraffic(
    {
      killSwitch: true,
      killSwitchStrict: true,
      defaultTraffic: "direct",
    },
    current
  );
  assert.equal(imported, "vpn");
  assert.equal(
    normalizeImportedDefaultTraffic(
      { defaultTraffic: imported },
      { ...current, killSwitch: true, killSwitchStrict: true }
    ),
    "vpn"
  );
});

test("backup preview exposes coercion when strict is imported without a fallback", () => {
  assert.equal(
    normalizeImportedDefaultTraffic(
      { killSwitch: true, killSwitchStrict: true },
      {
        killSwitch: false,
        killSwitchStrict: false,
        defaultTraffic: "direct",
      }
    ),
    "vpn"
  );
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
