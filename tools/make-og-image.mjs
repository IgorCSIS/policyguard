/**
 * Rasterize assets/og-image.html into web/public/og-image.png.
 *
 * Run by hand when the card changes, not as part of any build. The PNG is
 * committed, so shipping the site needs neither Chromium nor Playwright and
 * the build stays a plain `vite build` with no browser in it.
 *
 *   node tools/make-og-image.mjs
 *
 * Point CHROMIUM_PATH at the binary if it is not where Playwright puts it.
 */

import { chromium } from "playwright-core";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const SOURCE = join(ROOT, "assets", "og-image.html");
const TARGET = join(ROOT, "web", "public", "og-image.png");

// Open Graph consumers expect exactly this. A card that is not 1200x630 gets
// cropped differently by every one of them.
const WIDTH = 1200;
const HEIGHT = 630;

const browser = await chromium.launch({
  executablePath: process.env.CHROMIUM_PATH || "/opt/pw-browsers/chromium-1194/chrome-linux/chrome",
});
const page = await browser.newPage({ viewport: { width: WIDTH, height: HEIGHT }, deviceScaleFactor: 1 });
await page.goto(pathToFileURL(SOURCE).href, { waitUntil: "networkidle" });
await page.screenshot({ path: TARGET, clip: { x: 0, y: 0, width: WIDTH, height: HEIGHT } });
await browser.close();

console.log(`Wrote ${TARGET} at ${WIDTH}x${HEIGHT}`);
