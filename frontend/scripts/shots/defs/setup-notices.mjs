// A fresh, unconfigured Datasette as an admin: no encryption key, no OAuth
// client (with the redirect URI to register), and no --internal database.

import { defineShot } from "../defineShot.mjs";

export default defineShot({
  name: "setup-notices",
  server: "setup",
  path: "/-/google-credentials",
  async prepare(page) {
    await page.locator(".notice").nth(2).waitFor();
  },
});
