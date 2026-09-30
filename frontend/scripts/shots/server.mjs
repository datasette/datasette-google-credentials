// Boot / tear down the throwaway datasettes the screenshots run against.
//
// Two kinds of server, each started only if a requested shot needs it:
//
//   * "seeded": --internal file DB, a throwaway Fernet key, a fake OAuth
//     client (so "Connect Google" shows and no setup notice does), every
//     Google URL pointed at a closed local port, and the seed plugin's demo
//     credentials + acl grants.
//   * "setup": nothing configured and no --internal (temp internal DB), so
//     the page shows every setup notice: no encryption key, no OAuth client,
//     credentials lost on restart.
//
// Each server gets a fresh temp dir (config, plugins dir, internal DB) and a
// free port. datasette is a grandchild of `uv run`, so it is spawned in its
// own process group and teardown signals that group by the child's PID: only
// processes this harness started are ever stopped.

import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import {
  copyFileSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  BLOCKED_GOOGLE_URLS,
  DEMO_REDIRECT_URI,
  SEED_PLUGIN,
  sleep,
} from "./config.mjs";

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");

// A Fernet key (urlsafe base64 of 32 random bytes, padded). Nothing is
// decrypted during the shots; the key only makes encryption "configured".
function throwawayFernetKey() {
  return randomBytes(32)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

function freePort() {
  if (process.env.SHOTS_PORT) return Promise.resolve(+process.env.SHOTS_PORT);
  return new Promise((resolvePort, reject) => {
    const srv = createServer();
    srv.unref();
    srv.on("error", reject);
    srv.listen(0, "127.0.0.1", () => {
      const { port } = srv.address();
      srv.close(() => resolvePort(port));
    });
  });
}

const LOAD_PLUGINS = [
  "datasette-google-auth",
  "datasette-acl",
  "datasette-acl-share",
  "datasette-user-profiles", // the share dialog's People search
  "datasette-vite",
  "datasette-plugin-router",
];

const PERMISSIONS = {
  "google-auth-connect": true,
  "google-auth-add-service-account": true,
  "google-auth-admin": { id: "alice" },
};

function datasetteConfig(kind) {
  if (kind === "seeded") {
    return {
      permissions: PERMISSIONS,
      plugins: {
        "datasette-google-auth": {
          "encryption-key": throwawayFernetKey(),
          client_id: "demo-client.apps.googleusercontent.com",
          client_secret: "demo-not-a-secret",
          google_base_urls: BLOCKED_GOOGLE_URLS,
        },
        shots_seed: { seed: true },
      },
    };
  }
  if (kind === "setup") {
    return {
      permissions: PERMISSIONS,
      plugins: {
        "datasette-google-auth": { redirect_uri: DEMO_REDIRECT_URI },
      },
    };
  }
  throw new Error(`Unknown server kind: ${kind}`);
}

async function reachable(base) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), 500);
  try {
    const resp = await fetch(`${base}/-/google-auth/api/status`, {
      signal: ctrl.signal,
    });
    return resp.status < 500;
  } catch {
    return false;
  } finally {
    clearTimeout(t);
  }
}

export async function startServer(kind) {
  const dir = mkdtempSync(join(tmpdir(), "datasette-google-auth-shots-"));
  const pluginsDir = join(dir, "plugins");
  const configPath = join(dir, "datasette.json");
  const internal = join(dir, "internal.db");
  mkdirSync(pluginsDir);
  copyFileSync(SEED_PLUGIN, join(pluginsDir, basename(SEED_PLUGIN)));
  writeFileSync(configPath, JSON.stringify(datasetteConfig(kind), null, 2));

  const port = await freePort();
  const base = `http://127.0.0.1:${port}`;
  if (await reachable(base)) {
    throw new Error(`Something is already serving on ${port}.`);
  }

  const args = ["run", "datasette", "-c", configPath];
  if (kind === "seeded") args.push("--internal", internal);
  args.push("--plugins-dir", pluginsDir, "-h", "127.0.0.1", "-p", String(port));

  const child = spawn("uv", args, {
    cwd: REPO,
    stdio: ["ignore", "pipe", "pipe"],
    detached: true, // own process group, so teardown reaches datasette too
    env: {
      ...process.env,
      DATASETTE_SECRET: "shots-not-a-secret",
      // Only what the pages need: the dev group's debug plugins (e.g.
      // datasette-debug-gotham's user-switch widget) would cover the shots.
      // --plugins-dir plugins load regardless.
      DATASETTE_LOAD_PLUGINS: LOAD_PLUGINS.join(","),
      PYTHONHASHSEED: "0",
    },
  });
  let logs = "";
  child.stdout.on("data", (d) => (logs += d));
  child.stderr.on("data", (d) => (logs += d));

  const server = { kind, base, child, dir, logs: () => logs };
  const deadline = Date.now() + 60_000;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) {
      stopServer(server);
      throw new Error(`datasette (${kind}) exited early:\n${logs}`);
    }
    if (await reachable(base)) return server;
    await sleep(250);
  }
  stopServer(server);
  throw new Error(`datasette (${kind}) did not become ready in 60s:\n${logs}`);
}

export function stopServer(server) {
  if (!server) return;
  const { child, dir } = server;
  if (child.exitCode === null) {
    try {
      process.kill(-child.pid, "SIGTERM"); // negative pid = our process group
    } catch {
      try {
        child.kill("SIGTERM");
      } catch {
        /* already gone */
      }
    }
  }
  rmSync(dir, { recursive: true, force: true });
}
