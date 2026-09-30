#!/usr/bin/env node
// Documentation-screenshot harness for datasette-google-auth.
//
//   node frontend/scripts/screenshots.mjs               # all shots
//   node frontend/scripts/screenshots.mjs index admin   # a subset
//
// SELF-CONTAINED: boots throwaway `uv run datasette` servers on free ports
// (a seeded one, and an unconfigured one for the setup notices), seeds demo
// credentials straight into the internal DB with the dev-only plugin
// scripts/shots_seed.py, drives headless Chromium and writes PNGs to
// docs/screenshots/. Run via `just shots`, which builds the frontend first
// so shots reflect current code. Nothing contacts Google.
//
// The harness lives in shots/:
//   * shots/config.mjs        constants + out(name)
//   * shots/server.mjs        boot/teardown of the throwaway datasettes
//   * shots/helpers.mjs       browser context, STABILITY_CSS
//   * shots/defineShot.mjs    per-shot new context → prepare → capture
//   * shots/defs/<name>.mjs   ONE FILE PER SHOT, auto-discovered below.

import { chromium } from "playwright";
import { readdirSync } from "node:fs";
import { mkdir } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { startServer, stopServer } from "./shots/server.mjs";
import { OUT } from "./shots/config.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const DEFS_DIR = resolve(HERE, "shots/defs");

// Every shots/defs/<name>.mjs default-exports a descriptor whose `name`
// must equal its filename.
async function loadShots() {
  const shots = new Map();
  for (const file of readdirSync(DEFS_DIR).sort()) {
    if (!file.endsWith(".mjs")) continue;
    const expected = file.slice(0, -4);
    const mod = await import(pathToFileURL(resolve(DEFS_DIR, file)).href);
    const shot = mod.default;
    if (!shot?.name) throw new Error(`${file}: missing default-exported shot`);
    if (shot.name !== expected) {
      throw new Error(`${file}: shot name "${shot.name}" must match filename`);
    }
    shots.set(shot.name, shot);
  }
  return shots;
}

async function main() {
  const requested = process.argv.slice(2);
  const shots = await loadShots();

  const unknown = requested.filter((n) => !shots.has(n));
  if (unknown.length) {
    console.error(`Unknown shot(s): ${unknown.join(", ")}`);
    console.error(`Available: ${[...shots.keys()].join(", ")}`);
    process.exit(1);
  }
  const toRun = requested.length ? requested : [...shots.keys()];

  await mkdir(OUT, { recursive: true });

  const servers = new Map();
  let browser;
  const cleanup = () => {
    for (const server of servers.values()) stopServer(server);
    servers.clear();
  };
  process.on("SIGINT", () => (cleanup(), process.exit(130)));
  process.on("SIGTERM", () => (cleanup(), process.exit(143)));

  const skipped = [];
  try {
    browser = await chromium.launch();
    for (const name of toRun) {
      const shot = shots.get(name);
      if (!servers.has(shot.server)) {
        servers.set(shot.server, await startServer(shot.server));
      }
      const result = await shot.run(browser, servers.get(shot.server));
      if (result.skipped) {
        skipped.push(name);
        console.log(`- ${name} skipped: ${result.skipped}`);
      } else {
        console.log(`✓ ${name} → ${result.path}`);
      }
    }
  } finally {
    if (browser) await browser.close();
    cleanup();
  }
  if (skipped.length) {
    console.log(
      `Skipped (existing PNGs left as they were): ${skipped.join(", ")}`,
    );
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
