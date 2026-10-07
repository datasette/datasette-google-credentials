// Shared constants for the documentation-screenshot harness.

import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));

// Dev-only seed plugin (see its docstring). server.mjs copies it into a
// throwaway --plugins-dir: scripts/ also holds scripts that mustn't load as
// plugins.
export const SEED_PLUGIN = resolve(HERE, "../../../scripts/shots_seed.py");

// Output: PNGs committed under docs/screenshots, named after the shot.
export const OUT = resolve(HERE, "../../../docs/screenshots");
export const out = (name) => resolve(OUT, `${name}.png`);

// Every shot browses as alice (a google-credentials-admin), via the seed plugin's
// actor_from_request header. No cookie signing needed.
export const ACTOR_HEADER = "x-shots-actor";
export const ACTOR = "alice";

// Default capture geometry. deviceScaleFactor:2 → crisp retina PNGs.
// Timezone + locale pin formatTimestamp()'s toLocaleString output.
export const VIEWPORT = { width: 1000, height: 800 };
export const DEVICE_SCALE_FACTOR = 2;
export const TIMEZONE = "UTC";
export const LOCALE = "en-US";

// Shown on the setup-notices shot instead of http://localhost:<free port>/…,
// so the PNG doesn't depend on the port.
export const DEMO_REDIRECT_URI =
  "https://datasette.example.com/-/google-credentials/oauth/callback";

// Google URLs for the seeded server: a closed local port, so nothing can
// reach Google even if a shot clicked the wrong thing.
const NOWHERE = "http://127.0.0.1:9";
export const BLOCKED_GOOGLE_URLS = {
  oauth_authorize: `${NOWHERE}/o/oauth2/v2/auth`,
  oauth_token: `${NOWHERE}/token`,
  oauth_revoke: `${NOWHERE}/revoke`,
  userinfo: `${NOWHERE}/v1/userinfo`,
};

export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
