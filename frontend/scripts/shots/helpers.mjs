// Page-stabilization helpers shared by the shot definitions.

import {
  ACTOR,
  ACTOR_HEADER,
  DEVICE_SCALE_FACTOR,
  LOCALE,
  TIMEZONE,
  VIEWPORT,
} from "./config.mjs";

// Injected on every navigation: kill the caret, transitions and animations,
// so re-runs produce no binary diff. ::backdrop matters: core's modal
// backdrop fades in, and a mid-fade blur differs run to run.
export const STABILITY_CSS = `
  *, *::before, *::after, ::backdrop {
    caret-color: transparent !important;
    transition: none !important;
    animation: none !important;
  }
`;

// Nothing on these pages is relative to "now": timestamps are the seed's
// fixed values, formatted in the pinned timezone/locale. So there is nothing
// to freeze beyond the stability stylesheet; this waits for web fonts so
// text metrics don't vary between runs.
export async function settle(page) {
  await page.evaluate(() => document.fonts.ready);
}

// New browser context browsing as alice, with retina scale, a fixed
// timezone/locale and the stability stylesheet on every document.
export async function makeContext(browser, { viewport = VIEWPORT } = {}) {
  const ctx = await browser.newContext({
    viewport,
    deviceScaleFactor: DEVICE_SCALE_FACTOR,
    timezoneId: TIMEZONE,
    locale: LOCALE,
    reducedMotion: "reduce",
    extraHTTPHeaders: { [ACTOR_HEADER]: ACTOR },
  });
  await ctx.addInitScript((css) => {
    const inject = () => {
      const style = document.createElement("style");
      style.textContent = css;
      document.head?.appendChild(style);
    };
    if (document.head) inject();
    document.addEventListener("DOMContentLoaded", inject);
  }, STABILITY_CSS);
  return ctx;
}
