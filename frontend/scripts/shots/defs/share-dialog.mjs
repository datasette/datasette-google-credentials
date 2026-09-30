// datasette-acl-share's dialog on alice's "Reports bot" service account:
// alice (Manager), bob (Editor) and carol (User). Skipped when that sibling's
// bundle isn't built (the page then has no Share buttons).

import { defineShot } from "../defineShot.mjs";

export default defineShot({
  name: "share-dialog",
  path: "/-/google-auth",
  capture: "viewport",
  async prepare(page) {
    await page.locator(".cards > li").nth(3).waitFor();
    const card = page.locator(".cards > li", { hasText: "Reports bot" });
    if (!(await card.locator("datasette-acl-share-dialog").count())) {
      return "skip: datasette-acl-share's frontend isn't built (no Share buttons)";
    }
    await card.locator(".datasette-acl-share__trigger").click();
    const dialog = card.locator("dialog[open]");
    await dialog.waitFor();
    await dialog.getByText("carol").first().waitFor();
  },
});
