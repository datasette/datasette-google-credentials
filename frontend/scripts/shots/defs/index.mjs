// The management page as alice: two Google accounts (one broken, with
// Reconnect), her own service account (Manager) and bob's, shared with her
// as User.

import { defineShot } from "../defineShot.mjs";

export default defineShot({
  name: "index",
  path: "/-/google-credentials",
  async prepare(page) {
    await page.locator(".cards > li").nth(3).waitFor();
    await page.locator(".badge-broken").waitFor();
    // Share buttons appear once datasette-acl-share's element is defined
    // (only if its bundle is built).
    if (await page.locator("datasette-acl-share-dialog").count()) {
      await page.locator(".datasette-acl-share__trigger").first().waitFor();
    }
  },
});
