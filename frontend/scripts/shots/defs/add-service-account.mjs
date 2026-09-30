// The "Add a service account" dialog with a label and a pasted key, showing
// the client-side peek at its client_email. Never submitted: "Test and save"
// would exchange the key with Google.

import { defineShot } from "../defineShot.mjs";

// Obviously fake: enough for the peek (type + client_email), no key material.
const DEMO_KEY = JSON.stringify(
  {
    type: "service_account",
    project_id: "demo-project",
    private_key_id: "demo",
    private_key: "(demo: not a real key)",
    client_email: "sheets-sync@demo-project.iam.gserviceaccount.com",
  },
  null,
  2,
);

export default defineShot({
  name: "add-service-account",
  path: "/-/google-auth",
  capture: "viewport",
  async prepare(page) {
    await page.getByRole("button", { name: "Add service account" }).click();
    const dialog = page.getByRole("dialog");
    await dialog.getByLabel("Label").fill("Sheets sync");
    await dialog.getByLabel("JSON key").fill(DEMO_KEY);
    await dialog.locator(".peek").waitFor();
  },
});
