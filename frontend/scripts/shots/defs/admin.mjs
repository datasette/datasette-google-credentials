// "All Google credentials" (google-credentials-admin): every credential with its
// owner's display name, type and status. Information and Delete only.

import { defineShot } from "../defineShot.mjs";

export default defineShot({
  name: "admin",
  path: "/-/google-credentials/admin",
  async prepare(page) {
    await page.locator("table.rows-and-columns tbody tr").nth(5).waitFor();
  },
});
