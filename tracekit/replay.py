"""replay.html (I5, V2): a self-contained viewer for one bundle. It re-runs the verifier's checks
in the browser with WebCrypto (SHA-256 chain, Ed25519 record and checkpoint signatures, counter,
policy hash, capture sources, gaps, tampering, approvals, opt-in capture) and shows what the run
did, with every event labelled by the capture path that recorded it. Schema validation and
independent witness checks need `tracekit verify`."""
import json

PAGE = r"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Tracekit evidence bundle</title>
<style>
:root{--bg:#fbfaf7;--fg:#17181a;--muted:#62646a;--line:#e3e1db;--card:#fff;--ok:#1d7a4a;--warn:#9a6400;--bad:#b3261e;--acc:#2a5bd7;--chip:#f0eee8}
@media (prefers-color-scheme:dark){:root{--bg:#141517;--fg:#ececea;--muted:#a2a3a7;--line:#2d2f33;--card:#1c1d20;--ok:#52c285;--warn:#e0a64a;--bad:#ff7a70;--acc:#86a8ff;--chip:#26282c}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 system-ui,sans-serif;padding:0 16px 48px}
main{max-width:1180px;margin:0 auto}h1{font-size:22px;margin:24px 0 4px}h2{font-size:16px;margin:22px 0 8px}p{margin:0 0 8px;color:var(--muted);max-width:80ch}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:8px;margin:12px 0}
.tile{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px 12px}.tile .k{color:var(--muted);font-size:12px}.tile .v{font-size:18px;font-weight:600}
.checks{display:grid;gap:6px;margin:8px 0}.c{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:8px 12px}
.c ul{margin:4px 0 0 18px;padding:0}.b{font:600 12px ui-monospace,monospace;padding:1px 6px;border-radius:4px;margin-right:8px}
.pass{color:var(--ok)}.fail{color:var(--bad)}.warn{color:var(--warn)}
.banner{border-radius:8px;padding:10px 14px;margin:12px 0;font-weight:600;border:1px solid var(--line);background:var(--card)}
.banner.bad{border-color:var(--bad);color:var(--bad)}.banner.warn{border-color:var(--warn);color:var(--warn)}.banner.ok{border-color:var(--ok);color:var(--ok)}
.chip{display:inline-block;font:12px ui-monospace,monospace;background:var(--chip);border-radius:4px;padding:0 6px;margin:0 4px 2px 0}
table{border-collapse:collapse;width:100%;font:12px ui-monospace,monospace}th,td{text-align:left;padding:4px 6px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:500;position:sticky;top:0;background:var(--card)}.wrap{overflow:auto;max-height:70vh;background:var(--card);border:1px solid var(--line);border-radius:8px}
td.x{max-width:560px;word-break:break-word}.el{color:var(--muted)}.low{color:var(--warn)}
label{color:var(--muted);font-size:13px;margin-right:12px}
</style></head><body><main>
<h1>Tracekit evidence bundle</h1>
<p id="meta"></p>
<div id="banner" class="banner">Checking…</div>
<p>Tracekit proves what its capture path recorded and that it has not changed since it was signed and checkpointed. It does not prove intent, complete coverage, or that reported results are real. This page re-runs the checks in your browser; schema validation and independent witness checks need <code>tracekit verify --witness …</code>.</p>
<div class="grid" id="tiles"></div>
<h2>Checks</h2><div class="checks" id="checks"></div>
<h2>Coverage</h2><div class="c" id="cov"></div>
<h2>Events</h2>
<p><label><input type="checkbox" id="onlyfind"> only findings (denied, held, gaps, tampering, errors)</label><label><input type="checkbox" id="showel"> show elided records</label></p>
<div class="wrap"><table><thead><tr><th>seq</th><th>time</th><th>run</th><th>agent</th><th>source</th><th>type</th><th>details</th></tr></thead><tbody id="rows"></tbody></table></div>
</main>
<script>
const M=__MANIFEST__, R=__RECORDS__, C=__CHECKPOINTS__, COV=__COVERAGE__, POL=__POLICIES__;
const TRUST={hook:"reported by a hook process (any process running as the agent's user can send these)",proxy:"observed at the model API boundary",transcript:"harness-reported, lower trust",sdk:"reported by an instrumented app",migrated:"converted from v0.1",signer:"written by tracekitd"};
const esc=s=>String(s??"").replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
function cp(a,b){const x=Array.from(a),y=Array.from(b),n=Math.min(x.length,y.length);for(let i=0;i<n;i++){const d=x[i].codePointAt(0)-y[i].codePointAt(0);if(d)return d;}return x.length-y.length;}
function canon(v){if(v===null||typeof v!=="object")return JSON.stringify(v);if(Array.isArray(v))return"["+v.map(canon).join(",")+"]";
 return"{"+Object.keys(v).sort(cp).map(k=>JSON.stringify(k)+":"+canon(v[k])).join(",")+"}";}
const enc=new TextEncoder(), hex=b=>[...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,"0")).join("");
const b64=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
async function sha(s){return hex(await crypto.subtle.digest("SHA-256",enc.encode(s)));}
const results=[];
function add(name,status,detail,problems){results.push(status);const d=document.createElement("div");d.className="c";
 d.innerHTML=`<span class="b ${status}">${status.toUpperCase()}</span><b>${esc(name)}</b>${detail?" — "+esc(detail):""}`+
 (problems&&problems.length?"<ul>"+problems.slice(0,12).map(p=>`<li class="${status}">${esc(p)}</li>`).join("")+"</ul>":"");
 document.getElementById("checks").appendChild(d);}
function tile(k,v,cls){const d=document.createElement("div");d.className="tile";d.innerHTML=`<div class="k">${esc(k)}</div><div class="v ${cls||""}">${esc(v)}</div>`;document.getElementById("tiles").appendChild(d);}
function val(c){return c&&("value" in c)?JSON.stringify(c.value):(c&&c.hash?c.hash.slice(0,19)+"…":"");}
function summary(e){const d=e.data||{};
 if(e.type==="tool.call"){const i=d.input||{};return d.name+" "+Object.keys(i).map(k=>k+"="+val(i[k])).join(" ");}
 if(e.type==="policy.decision")return d.decision+" "+(d.rule_ids||[]).join(",")+" "+(d.reasons||[]).join("; ");
 if(e.type==="tool.result")return (d.ok?"ok":"FAILED")+(d.duration_ms!=null?" "+d.duration_ms+"ms":"")+" output "+val(d.output);
 if(e.type==="run.start")return `${d.agent&&d.agent.name} model=${d.model||"?"} fail_mode=${d.fail_mode} policy=${d.policy&&d.policy.version} signer=${d.signer_isolation} user=${d.os_user}${d.os_user_attested?" (attested)":""} sources=${(d.capture_sources||[]).join("+")}`;
 if(e.type==="checkpoint")return `head ${d.head_seq} → ${(d.witnesses||[]).join(", ")||"no witness reached"}`;
 if(e.type==="model.exchange")return d.phase==="request"?`request ${d.model||""} ${d.streamed?"(stream)":""} results sent: ${(d.tool_results_sent||[]).length}`:
   `response ${d.status} ${d.stop_reason||""} tools: ${(d.tool_uses||[]).map(t=>t.name+" "+t.id.slice(-8)).join(", ")||"none"} · ${d.duration_ms}ms (+${d.added_latency_ms}ms)`;
 if(e.type==="approval")return `${d.decision} by ${d.approver} via ${d.channel} after ${d.wait_ms}ms`;
 if(e.type==="trace.tamper")return `${d.kind||"changed"}: ${d.path} length ${d.before&&d.before.length} → ${d.after&&d.after.length}`;
 if(e.type==="capture.gap")return `${d.kind?"["+d.kind+"] ":""}${d.reason}`;
 if(e.type==="user.prompt"||e.type==="model.message")return val(d.content);
 return JSON.stringify(d).slice(0,300);}
function finding(e){return e.type==="capture.gap"||e.type==="trace.tamper"||e.type==="error"||e.type==="approval"||(e.type==="policy.decision"&&(e.data.decision==="deny"||e.data.decision==="ask"));}
(async()=>{
 const runs=M.selection.runs, ev=R.filter(r=>!r.elided).map(r=>r.event), sel=ev.filter(e=>runs.includes(e.run_id));
 document.getElementById("meta").textContent=`runs ${runs.join(", ")} · records 0..${M.seq_range[1]} · signer ${M.kid} · tracekit ${M.tracekit_version}`;
 // chain + counter
 let prev="0".repeat(64),bad=[],n=0;const hashes={};
 for(const r of R){const seq=r.elided?r.seq:r.event.seq, ph=r.elided?r.prev_hash:r.event.prev_hash;
  if(!r.elided){const h=await sha(canon(r.event));if(h!==r.hash)bad.push(`seq ${seq}: hash mismatch (event content was edited)`);}
  if(seq!==n)bad.push(`seq ${seq}: expected ${n} (record deleted, inserted or reordered)`);if(ph!==prev)bad.push(`seq ${seq}: chain broken`);prev=r.hash;n=seq+1;hashes[seq]=r.hash;}
 add("chain intact",bad.length?"fail":"pass",bad.length?"":`${R.length} records re-hashed from genesis`,bad);
 const seqs=Object.keys(hashes).map(Number).sort((a,b)=>a-b);const holes=[];seqs.forEach((s,i)=>{if(i&&s!==seqs[i-1]+1)holes.push(`missing ${seqs[i-1]+1}..${s-1}`)});
 add("counter has no gaps",holes.length?"fail":"pass",holes.length?"":`seq 0..${seqs[seqs.length-1]} contiguous`,holes);
 // signatures + checkpoints
 let key=null;try{key=await crypto.subtle.importKey("raw",b64(M.public_key_b64),{name:"Ed25519"},false,["verify"]);}catch(e){}
 if(!key){add("signatures valid","warn","this browser has no WebCrypto Ed25519; run tracekit verify");}
 else{let sb=[];for(const r of R){const seq=r.elided?r.seq:r.event.seq, ph=r.elided?r.prev_hash:r.event.prev_hash;
   const ok=await crypto.subtle.verify({name:"Ed25519"},key,b64(r.sig),enc.encode(canon({hash:r.hash,prev_hash:ph,seq})));if(!ok)sb.push(`seq ${seq}: signature invalid`);}
  add("signatures valid",sb.length?"fail":"pass",sb.length?"":`${R.length} Ed25519 signatures valid (${M.kid})`,sb);
  let cb=[],cov=false;const last=Math.max(...sel.map(e=>e.seq));
  for(const c of C){const body={...c};delete body.sig;const ok=await crypto.subtle.verify({name:"Ed25519"},key,b64(c.sig),enc.encode(canon(body)));
   if(!ok)cb.push(`checkpoint ${c.head_seq}: signature invalid or wrong key`);else if(!(c.head_seq in hashes))cb.push(`checkpoint ${c.head_seq}: beyond the last record (truncated)`);
   else if(hashes[c.head_seq]!==c.head_hash)cb.push(`checkpoint ${c.head_seq}: head does not match (chain rewritten)`);else if(c.head_seq>=last)cov=true;}
  add("head matches a checkpoint",cb.length?"fail":(cov?"pass":"warn"),cb.length?"":(cov?"covered by a signed checkpoint (independent witness: tracekit verify --witness)":"records after the last checkpoint are signed but not witnessed"),cb);}
 // policy
 const pp=[];for(const s of sel.filter(e=>e.type==="run.start")){const h=s.data.policy.hash,p=POL[h.split(":")[1]];
  if(!p){pp.push(`run ${s.run_id}: policy snapshot missing`);continue;}if("sha256:"+await sha(canon(p))!==h)pp.push(`run ${s.run_id}: snapshot hash differs from run.start`);
  const ids=new Set(["TK-SCOPE",...["deny","ask","flag"].flatMap(k=>(p[k]||[]).map(r=>r.id))]);
  for(const d of sel.filter(e=>e.type==="policy.decision"&&e.run_id===s.run_id))for(const i of d.data.rule_ids)if(!ids.has(i))pp.push(`seq ${d.seq}: unknown rule ${i}`);}
 add("policy hash consistent",pp.length?"fail":"pass",pp.length?"":"policy snapshots match run.start; every cited rule exists",pp);
 // sources
 const cnt={};sel.forEach(e=>cnt[e.source]=(cnt[e.source]||0)+1);const decl=[...new Set(sel.filter(e=>e.type==="run.start").flatMap(e=>e.data.capture_sources||[]))];
 const miss=decl.filter(x=>!cnt[x]);add("capture sources",miss.length?"warn":"pass",Object.entries(cnt).map(([k,v])=>`${k}: ${v} (${TRUST[k]||k})`).join("; "),miss.map(x=>`declared ${x} but none recorded`));
 const gaps=ev.filter(e=>e.type==="capture.gap"&&(runs.includes(e.run_id)||e.run_id==="_signer"));
 add("capture gaps",gaps.length?"warn":"pass",gaps.length?"":"none",gaps.map(e=>`seq ${e.seq}: ${summary(e)}`));
 const tt=ev.filter(e=>e.type==="trace.tamper"&&(runs.includes(e.run_id)||e.run_id==="_signer"));
 add("harness transcript unchanged",tt.length?"warn":"pass",tt.length?"TRACE TAMPERING DETECTED":`${sel.filter(e=>e.transcript).length} transcript marks matched`,tt.map(e=>`seq ${e.seq}: ${summary(e)}`));
 const ap=sel.filter(e=>e.type==="approval");if(ap.length)add("approvals",ap.some(e=>e.data.decision==="self_approval_refused"||(e.data.decision==="approve"&&e.data.same_user))?"warn":"pass","",ap.map(e=>`seq ${e.seq}: ${summary(e)}${e.data.same_user&&e.data.decision==="approve"?" (same user, not trustworthy)":""}`));
 const cw=(COV.warnings||[]).concat((COV.unsupported_used||[]).map(u=>"unsupported path used: "+u));
 add("coverage",cw.length?"warn":"pass",COV.summary,cw);
 const st=sel.filter(e=>e.type==="run.start"), full=st.some(e=>e.data.content_capture==="full"||e.data.reasoning_capture);
 add("opt-in content capture",full?"warn":"pass",st.map(e=>`content_capture=${e.data.content_capture}, reasoning_capture=${e.data.reasoning_capture?"on":"off"}`).join("; "));
 // tiles
 const calls=sel.filter(e=>e.type==="tool.call").length, den=sel.filter(e=>e.type==="policy.decision"&&e.data.decision==="deny").length;
 tile("tool calls",calls);tile("blocked",den,den?"fail":"");tile("held for approval",sel.filter(e=>e.type==="policy.decision"&&e.data.decision==="ask").length);
 tile("model exchanges",sel.filter(e=>e.type==="model.exchange"&&e.data.phase==="response").length);tile("capture gaps",gaps.length,gaps.length?"warn":"");
 tile("tampering",tt.length,tt.length?"fail":"");tile("fail mode",[...new Set(st.map(e=>e.data.fail_mode))].join(",")||"?");
 tile("signer",[...new Set(st.map(e=>e.data.signer_isolation))].join(",")||"?",st.some(e=>e.data.signer_isolation==="same-user")?"warn":"");
 const bn=document.getElementById("banner");
 if(results.includes("fail")){bn.className="banner bad";bn.textContent="VERIFICATION FAILED: the bundle was changed after it was signed, or is incomplete.";}
 else if(tt.length){bn.className="banner bad";bn.textContent="Bundle intact, but the agent's harness transcript was modified during the run (trace tampering).";}
 else if(results.includes("warn")){bn.className="banner warn";bn.textContent="Bundle intact, with warnings about what was not observed. Read the checks below.";}
 else{bn.className="banner ok";bn.textContent="Bundle intact: every record re-hashed and every signature verified.";}
 const cv=document.getElementById("cov");cv.innerHTML=`<b>${esc(COV.summary)}</b> · sandbox ${esc((COV.sandbox||[]).join(", "))}`+
  "<p>Observed: "+(COV.observed||[]).map(x=>`<span class="chip">${esc(x)}</span>`).join("")+"</p>"+
  (COV.inferred&&COV.inferred.length?"<p class='low'>Inferred (lower trust): "+esc(COV.inferred.join("; "))+"</p>":"")+
  (COV.warnings.length?"<ul>"+COV.warnings.map(w=>`<li class="warn">${esc(w)}</li>`).join("")+"</ul>":"")+
  (COV.unsupported_used&&COV.unsupported_used.length?"<ul>"+COV.unsupported_used.map(w=>`<li class="warn">unsupported path used: ${esc(w)}</li>`).join("")+"</ul>":"")+
  "<p>Never covered: "+esc(COV.unsupported.join("; "))+"</p>";
 function draw(){const only=document.getElementById("onlyfind").checked, el=document.getElementById("showel").checked;
  document.getElementById("rows").innerHTML=R.filter(r=>r.elided?el&&!only:(!only||finding(r.event))).map(r=>r.elided?`<tr class="el"><td>${r.seq}</td><td colspan="6">elided (not in this selection) · hash ${r.hash.slice(0,16)}…</td></tr>`:
  `<tr><td>${r.event.seq}</td><td>${esc(r.event.ts.slice(11,23))}</td><td>${esc(r.event.run_id.slice(0,8))}</td><td>${esc(r.event.agent_id.slice(0,10))}</td><td class="${r.event.source==="transcript"?"low":""}" title="${esc(TRUST[r.event.source]||"")}">${esc(r.event.source)}${r.event.source==="transcript"?" ⚠":""}</td><td class="${r.event.type==="capture.gap"?"warn":(r.event.type==="trace.tamper"||(r.event.type==="policy.decision"&&r.event.data.decision==="deny")?"fail":"")}">${esc(r.event.type)}</td><td class="x">${esc(summary(r.event))}</td></tr>`).join("");}
 document.getElementById("onlyfind").onchange=draw;document.getElementById("showel").onchange=draw;draw();
})();
</script></body></html>"""


def _js(obj):
    return json.dumps(obj, ensure_ascii=False).replace("<", "\\u003c").replace(">", "\\u003e").replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")


def render(manifest, records, checkpoints, cov, policies=None):
    pols = {}
    for name, text in (policies or {}).items():
        try:
            pols[name.split("/")[-1].rsplit(".", 1)[0]] = json.loads(text)
        except ValueError:
            pass
    return (PAGE.replace("__MANIFEST__", _js(manifest)).replace("__RECORDS__", _js(records))
            .replace("__CHECKPOINTS__", _js(checkpoints)).replace("__COVERAGE__", _js(cov)).replace("__POLICIES__", _js(pols)))
