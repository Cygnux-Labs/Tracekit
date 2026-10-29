/**
 * The browser verifier: verify.html, which scripts/verify-page.mjs builds from this module, the verifier it imports and
 * page.html. The bundle and trust config a person chooses are read and verified in the page, whose Content Security
 * Policy lets it load and send nothing, so neither file leaves the browser. It reports what the TypeScript CLI does: a
 * bundle that relies on a check this verifier doesn't implement is UNVERIFIABLE, never VERIFIED. Without a trust config
 * it checks what needs no pinned key (verify's `trust` null). explain.ts says what the report means.
 *
 * The verification runs in a worker started from this same script (a blob: URL, which inherits the page's policy), so a
 * large bundle doesn't freeze the page; in the page itself where the browser refuses the worker.
 */
import { MEANING, asJson, asText, cliExit, nextSteps, sh, summarize, verdict } from "./explain.js";
import { type Report, VERSION, clean, readZip, verify } from "./index.js";

/** The page's samples (src/verify/sample/), base64: a clean bundle, a tampered copy and their trust config. */
declare const SAMPLES: Record<"sample.tkb" | "sample-tampered.tkb" | "sample.trust.json", string>;

type Job = { bundle: Uint8Array; trust: Uint8Array | null; names: { bundle: string; trust: string } };
type Result = { report: Report; code: number; summary: [string, string][] };

/** The report, and a summary of the runs when nothing failed (what a failed bundle says can't be relied on). */
async function work(job: Job): Promise<Result> {
  const { report, code } = await verify(job.bundle, job.trust, job.names);
  const summary = !report.failures.length && report.checks.some((c) => c.check === "signatures")
    ? summarize(await readZip(job.bundle), report) : [];
  return { report, code, summary };
}

if (typeof document === "undefined")   // this script, as the page's worker: a report, or the error that stopped it
  addEventListener("message", async (e) => {
    try {
      postMessage(await work((e as MessageEvent).data));
    } catch (err) {
      postMessage({ error: String((err as Error)?.message ?? err) });
    }
  });
else page();

function page() {
  type Chosen = { name: string; bytes: Uint8Array } | null;
  const $ = (id: string) => document.getElementById(id) as HTMLElement & HTMLInputElement;
  const el = (tag: string, text = "", cls = "") => {
    const e = document.createElement(tag);
    if (text) e.textContent = text;
    if (cls) e.className = cls;
    return e;
  };
  let bundle: Chosen = null, trust: Chosen = null, turn = 0, worker: Worker | null = null, workers = true, url = "";
  let last = { text: "", json: "", name: "" };
  $("version").textContent = VERSION;

  /** `job` verified in a fresh worker (a newer job ends the one before it), else in the page. */
  function run(job: Job): Promise<Result> {
    worker?.terminate();
    if (workers) try {
      // this page's own script, by id: a browser extension may add a script element of its own first
      url ||= URL.createObjectURL(new Blob([$("verifier").textContent!], { type: "text/javascript" }));
      const w = worker = new Worker(url);   // classic: Chrome refuses module workers to file:// pages
      return new Promise((resolve, reject) => {
        w.onmessage = (e) => {
          w.terminate();
          if (e.data.error) reject(new Error(e.data.error));
          else resolve(e.data);
        };
        w.onerror = (e) => {   // refused (an older browser's policy, or file:// in some): verify here instead
          e.preventDefault();
          workers = false;
          resolve(work(job));
        };
        w.postMessage(job);
      });
    } catch {
      workers = false;
    }
    // lean: in the page, a bundle of 100k records holds the main thread for seconds; chunk the verifier if browsers
    // without blob: workers matter
    return work(job);
  }

  const read = async (f: File) => ({ name: f.name, bytes: new Uint8Array(await f.arrayBuffer()) });
  const unb64 = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
  const sampleTrust = { name: "sample.trust.json", bytes: unb64(SAMPLES["sample.trust.json"]) };

  async function choose(files: FileList | null | undefined) {
    if (trust === sampleTrust) trust = null;   // the samples' signer is not the one behind the person's own bundle
    for (const f of [...files ?? []]) {
      if (/\.json$/i.test(f.name)) trust = await read(f);
      else bundle = await read(f);
    }
    await show();
  }

  function command(text: string) {
    const row = el("div", "", "cmd"), copy = el("button", "copy");
    copy.setAttribute("type", "button");
    copy.setAttribute("aria-label", `Copy: ${text}`);
    copy.addEventListener("click", () => navigator.clipboard?.writeText(text));
    row.append(el("code", text), copy);
    return row;
  }

  async function show() {
    $("bundle-name").textContent = bundle?.name ?? "none chosen";
    $("trust-name").textContent = trust?.name ?? "none";
    $("clear-trust").hidden = !trust;
    if (!bundle) return;
    const mine = ++turn, names = { bundle: bundle.name, trust: trust?.name ?? null };
    $("result").hidden = true;   // the last bundle's verdict never stands under this one's name
    document.body.dataset.state = "verifying";
    $("busy").textContent = "Verifying...";
    $("busy").hidden = false;
    let result: Result;
    try {
      result = await run({ bundle: bundle.bytes, trust: trust?.bytes ?? null,
        names: { bundle: names.bundle, trust: names.trust ?? "TRUST.json" } });
    } catch (err) {   // never left at "Verifying...": say what stopped it and where else to check
      if (mine !== turn) return;
      $("result").hidden = true;
      $("busy").textContent = `Couldn't check this file: ${clean(String((err as Error)?.message ?? err))}. The `
        + `command-line verifier may say more: npx -y @cygnuxlabs/tracekit@latest verify ${sh(names.bundle)}`;
      document.body.dataset.state = "error";
      return;
    }
    if (mine !== turn) return;   // a later choice of files: its report wins
    const { report, code, summary } = result;
    const v = verdict(report, code);
    $("banner").className = `banner ${{ VERIFIED: "ok", FAILED: "bad", UNVERIFIABLE: "warn" }[v.word]}`;
    $("verdict-word").textContent = v.word;
    $("verdict-means").textContent = v.means;
    $("verdict-not").textContent = v.notMeans;
    const steps = nextSteps(report, code, names);
    $("next").hidden = !steps.length;
    $("steps").replaceChildren(...steps.map((s) => {
      const li = el("li", s.text);
      if (s.command) li.append(command(s.command));
      return li;
    }));
    $("summary-box").hidden = !summary.length;
    $("summary-title").textContent = code === 0 ? "what the bundle holds"
      : "what the bundle says it holds (not verified: see above)";
    $("summary").replaceChildren(...summary.flatMap(([k, val]) => [el("dt", k), el("dd", val)]));
    $("checks").replaceChildren(...report.checks.map((c) => {
      const d = el("details") as HTMLDetailsElement, s = el("summary"), line = el("span", "", "line");
      const tone = { pass: "ok", warn: "warn", fail: "bad" }[c.status];
      line.append(el("span", `[${c.status.toUpperCase()}]`, `status ${tone}`),
        ` ${c.check}` + (c.detail ? ` — ${clean(c.detail)}` : ""));
      s.append(line);
      d.append(s);
      for (const p of c.problems) d.append(el("div", clean(p), "problem"));   // one by one: a spread overflows the stack
      d.append(el("p", `What this means: ${MEANING[c.check]?.[c.status] ?? "see docs/verdicts.md."}`, "means"));
      d.open = c.status !== "pass" && c.problems.length > 0;
      return d;
    }));
    $("integrity").textContent = `Integrity: ${clean(report.integrity)}.`;
    $("assurance").textContent = `Assurance: ${clean(report.assurance)}.`;
    last = { text: asText(report, code), json: JSON.stringify(asJson(report, code), null, 2) + "\n", name: bundle.name };
    $("exit").textContent = last.text.trim().split("\n").at(-1) + cliExit(report);
    $("report").textContent = last.text;
    $("copied").textContent = "";
    $("result").hidden = false;
    $("busy").hidden = true;
    $("banner").scrollIntoView?.({ block: "nearest" });
    document.body.dataset.state = "done";
  }

  $("bundle").addEventListener("change", () => choose($("bundle").files));
  $("trust").addEventListener("change", async () => {
    const f = $("trust").files?.[0];
    if (f) trust = await read(f);
    await show();
  });
  $("clear-trust").addEventListener("click", () => {
    trust = null;
    $("trust").value = "";
    return show();
  });
  for (const [id, file] of [["sample-clean", "sample.tkb"], ["sample-tampered", "sample-tampered.tkb"]] as const)
    $(id).addEventListener("click", () => {
      bundle = { name: file, bytes: unb64(SAMPLES[file]) };
      trust = sampleTrust;
      return show();
    });
  $("copy").addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(last.text);
      $("copied").textContent = "Copied.";
    } catch {
      ($("report").parentElement as HTMLDetailsElement).open = true;
      getSelection()?.selectAllChildren($("report"));
      $("copied").textContent = "Selected: press Ctrl+C (Cmd+C on a Mac) to copy.";
    }
  });
  $("download").addEventListener("click", () => {
    const a = el("a") as HTMLAnchorElement;
    a.href = URL.createObjectURL(new Blob([last.json], { type: "application/json" }));
    a.download = `${last.name.replace(/\.[^.]*$/, "")}.verify.json`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  });
  const drop = $("drop");
  for (const t of ["dragenter", "dragover"])
    drop.addEventListener(t, (e) => {
      e.preventDefault();
      drop.classList.add("over");
    });
  drop.addEventListener("dragleave", () => drop.classList.remove("over"));
  drop.addEventListener("drop", (e) => {
    e.preventDefault();
    drop.classList.remove("over");
    return choose((e as DragEvent).dataTransfer?.files);
  });
  for (const t of ["dragover", "drop"])   // a file dropped beside the zone isn't opened in place of the page
    document.addEventListener(t, (e) => e.preventDefault());
}
