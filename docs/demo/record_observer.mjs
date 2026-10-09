// Records the observer while observer_scene.py runs, then writes docs/demo/observer.mp4 and observer.gif.
//   npm i playwright && npx playwright install chromium     (once, outside the repo)
//   PYTHON=<python with tracekit's deps> node docs/demo/record_observer.mjs [seconds=40]   (needs ffmpeg)
import { chromium } from "playwright";
import { spawn, execFileSync } from "node:child_process";
import { mkdtempSync, readdirSync, rmSync } from "node:fs";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";

const here = process.env.DEMO_DIR || dirname(fileURLToPath(import.meta.url));  // where the scene lives and outputs go
const seconds = Number(process.argv[2] || 26);
const scene = spawn(process.env.PYTHON || "python3", [join(here, "observer_scene.py")], { stdio: ["ignore", "pipe", "inherit"] });
const url = await new Promise((res, rej) => {
  scene.stdout.on("data", (b) => { const m = String(b).match(/observer: (\S+)/); if (m) res(m[1]); });
  scene.on("exit", () => rej(new Error("scene exited before the observer started")));
});
const dir = mkdtempSync(join(tmpdir(), "tk-video-"));
const browser = await chromium.launch();
const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, recordVideo: { dir, size: { width: 1440, height: 900 } } });
const page = await ctx.newPage();
await page.goto(url);
await page.waitForTimeout((seconds - 6) * 1000);
const blocked = page.locator("#tape tr", { hasText: "tracekitd" }).first();  // end on the agent that tried to stop the recorder
if (await blocked.count()) await blocked.click();
await page.waitForTimeout(6000);
await ctx.close();
await browser.close();
scene.kill("SIGINT");
const webm = join(dir, readdirSync(dir).find((f) => f.endsWith(".webm")));
const mp4 = join(here, "observer.mp4"), gif = join(here, "observer.gif");
execFileSync("ffmpeg", ["-loglevel", "error", "-y", "-i", webm, "-c:v", "libx264", "-pix_fmt", "yuv420p", "-crf", "26", "-movflags", "+faststart", mp4]);
execFileSync("ffmpeg", ["-loglevel", "error", "-y", "-i", webm, "-vf",
  "fps=4,scale=880:-1:flags=lanczos,split[a][b];[a]palettegen=max_colors=48:stats_mode=diff[p];[b][p]paletteuse=dither=none:diff_mode=rectangle", gif]);
rmSync(dir, { recursive: true, force: true });
console.log(`wrote ${mp4} and ${gif}`);
