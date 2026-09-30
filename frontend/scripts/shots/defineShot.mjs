// Turn a declarative shot descriptor into a runner.
//
// Each defs/<name>.mjs default-exports defineShot({...}); the filename must
// equal `name` (asserted by screenshots.mjs, no central registry).
//
// Descriptor fields:
//   name      required, must match the filename
//   server    "seeded" (default) or "setup" (see server.mjs)
//   viewport  context viewport (default VIEWPORT)
//   path      where to navigate, relative to the server
//   prepare   async (page) => void | "skip: <reason>": wait for readiness,
//             interact. Returning a "skip: …" string skips the shot.
//   capture   "page" (default): full page cropped at datasette's footer
//             (short pages otherwise pad the PNG with whitespace);
//             "viewport": just the viewport (for modal dialogs)

import { makeContext, settle } from "./helpers.mjs";
import { out } from "./config.mjs";

async function captureToFooter(page, path) {
  const height = await page.evaluate(() => {
    const footer = document.querySelector("footer.ft");
    if (!footer) return document.documentElement.scrollHeight;
    return Math.ceil(footer.getBoundingClientRect().bottom + window.scrollY);
  });
  const { width } = page.viewportSize();
  await page.screenshot({
    path,
    clip: { x: 0, y: 0, width, height },
    fullPage: true,
  });
}

export function defineShot(descriptor) {
  const { name } = descriptor;
  if (!name) throw new Error("defineShot: `name` is required");
  return {
    name,
    server: descriptor.server ?? "seeded",
    async run(browser, server) {
      const ctx = await makeContext(browser, { viewport: descriptor.viewport });
      // Anything the page would send to Google must not leave the browser.
      await ctx.route(/googleapis\.com|accounts\.google\.com/, (route) =>
        route.abort(),
      );
      // Shots only look: a POST (add, rotate, delete, share) could reach for
      // a token or change the seeded state.
      const writes = [];
      ctx.on("request", (req) => {
        if (req.method() !== "GET") writes.push(`${req.method()} ${req.url()}`);
      });
      try {
        const page = await ctx.newPage();
        const response = await page.goto(server.base + descriptor.path, {
          waitUntil: "domcontentloaded",
        });
        if (!response?.ok()) {
          throw new Error(
            `${name}: ${descriptor.path} → ${response?.status()}`,
          );
        }
        const result = descriptor.prepare
          ? await descriptor.prepare(page)
          : undefined;
        if (typeof result === "string" && result.startsWith("skip:")) {
          return { skipped: result.slice(5).trim() };
        }
        await settle(page);
        if (writes.length) {
          throw new Error(
            `${name} sent non-GET requests: ${writes.join(", ")}`,
          );
        }
        const path = out(name);
        if (descriptor.capture === "viewport") {
          await page.screenshot({ path });
        } else {
          await captureToFooter(page, path);
        }
        return { path };
      } finally {
        await ctx.close();
      }
    },
  };
}
