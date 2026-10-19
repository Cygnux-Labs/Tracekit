// Build dist/verify.html, the browser verifier, from tsc's output (run after `tsc -p .`): src/verify/page.html with
// dist/verify/web.js and the modules it imports inlined as one module script, each module in a function scope of its own,
// after the samples of src/verify/sample/, and a Content Security Policy that allows only that script and the page's
// style, by hash, and workers from blob: URLs (web.ts starts its own script as one, which inherits this policy), so the
// page loads and sends nothing. The same tree gives the same bytes (scripts/release/build.py builds it twice and compares).
// lean: regular expressions over tsc's output, not a bundler: the import and export forms below, and any other fails
// the build; use a bundler (after a dependency risk review) when the verifier's modules need more.
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";

const dist = new URL("../dist/verify/", import.meta.url);
const vars = new Map();   // module file -> the variable holding its exports, once its code is in `script`
let script = "";

async function inline(file, entry = false) {
  if (vars.has(file)) return vars.get(file);
  const local = /^(import|export) \{([^}]*)\} from "\.\/([\w.-]+\.js)";$/gm;
  for (const [, , , dep] of readFileSync(new URL(file, dist), "utf8").matchAll(local)) await inline(dep);
  const reexported = [];   // "name: __dep.name" of each `export { ... } from`
  const specs = (list) => list.split(",").map((s) => s.trim()).filter(Boolean).map((s) => s.split(/\s+as\s+/));
  const src = readFileSync(new URL(file, dist), "utf8")
    .replace(/^import (\w+) from "\.\/([\w.-]+\.json)" with \{ type: "json" \};$/gm,
      (_, name, json) => `const ${name} = ${JSON.stringify(JSON.parse(readFileSync(new URL(json, dist), "utf8")))};`)
    .replace(local, (_, kind, list, dep) => {
      if (kind === "import") return `const { ${specs(list).map(([a, b = a]) => `${a}: ${b}`).join(", ")} } = ${vars.get(dep)};`;
      reexported.push(...specs(list).map(([a, b = a]) => `${b}: ${vars.get(dep)}.${a}`));
      return "";
    })
    .replace(/^export (?=(async function|function|class|const|let) )/gm, "");
  const rest = src.match(/^(import|export)\b.*$/m);
  if (rest) throw new Error(`${file}: ${rest[0].slice(0, 80)}: not an import or export form this script inlines`);
  // the module's own exports, as its evaluation in Node lists them (the entry runs only in the page: it exports nothing)
  const names = entry ? [] : Object.keys(await import(new URL(file, dist)));
  const own = names.filter((n) => !reexported.some((r) => r.startsWith(`${n}: `)));
  const v = `__${file.replace(/\.js$/, "").replace(/\W/g, "_")}`;
  script += `const ${v} = (() => {\n${src}\nreturn { ${[...own, ...reexported].join(", ")} };\n})();\n`;
  vars.set(file, v);
  return v;
}

// the page's samples (scripts/verify_page_check.py --samples writes them), as base64 the script decodes
script += `const SAMPLES = ${JSON.stringify(Object.fromEntries(["sample.tkb", "sample-tampered.tkb", "sample.trust.json"]
  .map((n) => [n, readFileSync(new URL(`../src/verify/sample/${n}`, import.meta.url)).toString("base64")])))};\n`;
await inline("web.js", true);
if (/<\/script|<!--/i.test(script)) throw new Error("the script holds text that would end the page's script element");
const page = readFileSync(new URL("../src/verify/page.html", import.meta.url), "utf8");
const style = page.match(/<style>([\s\S]*?)<\/style>/)[1];
const hash = (s) => `'sha256-${createHash("sha256").update(s, "utf8").digest("base64")}'`;
const csp = `default-src 'none'; script-src ${hash(script)}; style-src ${hash(style)}; worker-src blob:; connect-src 'none'`;
writeFileSync(new URL("../verify.html", dist), page.replace("%CSP%", csp).replace("%SCRIPT%", () => script));
