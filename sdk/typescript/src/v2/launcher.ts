/**
 * Where the `tracekit` command is: $TRACEKIT_PYTHON's `-m tracekit`, else a pip-installed `tracekit` on PATH, else the
 * Python bundled in the installed @cygnux/tracekit-signer-<platform> package. Used by bin/tracekit.mjs and the v2
 * client's dev auto-spawn.
 */
import { existsSync } from "node:fs";
import { createRequire } from "node:module";
import { delimiter, dirname, join } from "node:path";

export const INSTALL_HINT = "no Tracekit signer found. Install one: `pip install 'tracekit-ai[signer]'` (puts `tracekit` " +
  "on PATH), or reinstall @cygnux/tracekit without --omit=optional so npm adds the signer package for this platform";

/** This platform's signer package suffix, as the optionalDependencies name them; null where none is built. */
export function platformKey(): string | null {
  let key = `${process.platform}-${process.arch}`;
  if (process.platform === "linux") {
    const header = (process.report?.getReport() as { header?: { glibcVersionRuntime?: string } } | undefined)?.header;
    if (!header?.glibcVersionRuntime) return null;   // musl: no bundle
    key += "-gnu";
  }
  return ["darwin-arm64", "linux-x64-gnu", "linux-arm64-gnu", "win32-x64"].includes(key) ? key : null;
}

/** The command line that runs `tracekit`, or null when there is none. */
export function signerCommand(env: NodeJS.ProcessEnv = process.env): string[] | null {
  if (env.TRACEKIT_PYTHON) return [env.TRACEKIT_PYTHON, "-m", "tracekit"];
  const tried = (env.TRACEKIT_LAUNCHER_TRIED ?? "").split(delimiter);
  const exe = process.platform === "win32" ? "tracekit.exe" : "tracekit";
  for (const dir of (env.PATH ?? "").split(delimiter)) {
    const p = join(dir, exe);
    if (dir && existsSync(p) && !tried.includes(p)) return [p];
  }
  const key = platformKey();
  if (!key) return null;
  try {
    const pkg = dirname(createRequire(import.meta.url).resolve(`@cygnux/tracekit-signer-${key}/package.json`));
    return [join(pkg, process.platform === "win32" ? "python/python.exe" : "python/bin/python3"), "-m", "tracekit"];
  } catch {
    return null;
  }
}

/**
 * The environment to run `cmd` in: it adds cmd[0] to $TRACEKIT_LAUNCHER_TRIED, so when the `tracekit` found on PATH is
 * this launcher again (npm's .bin link, a pnpm shim), that run looks past it instead of starting itself forever.
 */
export function signerEnv(cmd: string[], env: NodeJS.ProcessEnv = process.env): NodeJS.ProcessEnv {
  return { ...env, TRACEKIT_LAUNCHER_TRIED: [env.TRACEKIT_LAUNCHER_TRIED, cmd[0]].filter(Boolean).join(delimiter) };
}
